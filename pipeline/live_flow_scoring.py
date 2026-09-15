"""
live_flow_scoring.py

Branche le modèle "flux locaux" (train_local_flow_model.py) sur les alertes
live de la page « Alertes en direct » du dashboard, à la place du proxy de
sévérité level_to_band().

POURQUOI C'EST POSSIBLE (et pas seulement théorique)
----------------------------------------------------
Les alertes Suricata indexées par Wazuh portent un bloc `data.flow`
(bytes_toserver/toclient, pkts_toserver/toclient, ports, proto, app_proto).
On peut donc reconstruire, par alerte, les 10 features NetFlow v1 attendues
par le modèle local et scorer réellement l'alerte — vérifié : 281/300
alertes d'un échantillon récent portent ce bloc.

DEUX LIMITES MESURÉES, DOCUMENTÉES PLUTÔT QUE MASQUÉES
-----------------------------------------------------
Les alertes indexées ne contiennent PAS `flow.end` ni `tcp.tcp_flags`
(0/281 et 0/256 sur l'échantillon). Deux features sont donc forcées à 0
pour les lignes scorées en live :
  - FLOW_DURATION_MILLISECONDS (importance 0.0006 dans le modèle binaire)
  - TCP_FLAGS                  (importance 0.0103)
Poids cumulé ~1,1 % : le score binaire repose à 83 % sur IN_BYTES et 13 %
sur L4_DST_PORT, tous deux pleinement récupérables. L'impact du zéro forcé
est donc négligeable pour la bande de risque, mais il est réel et signalé.

REPLI EXPLICITE
---------------
Si le modèle local est absent, ou si les features reconstruites ne valident
pas le schéma (feature_schema.validate_local_flow_schema), ou si une alerte
ne porte pas de bloc flow exploitable, on retombe sur level_to_band() pour
la (les) ligne(s) concernée(s). Le repli n'est jamais silencieux : chaque
ligne porte son `band_source` ("model" ou "fallback") et un résumé est
retourné dans `meta`.
"""

import os
from datetime import datetime

import numpy as np
import pandas as pd

from feature_schema import LOCAL_FLOW_FEATURE_COLUMNS, FeatureSchemaError, validate_local_flow_schema
from flow_feature_extractor import (
    L7_PROTO_BY_APP_PROTO,
    L7_PROTO_UNKNOWN,
    PROTOCOL_NUMBERS,
)
from risk_scorer import RISK_BANDS


def level_to_band(level) -> str:
    """
    Proxy de repli, identique à dashboard.level_to_band (bande à partir de la
    sévérité Wazuh brute). Dupliqué ici pour que ce module reste importable
    sans dépendre de dashboard.py (qui exécute du code Streamlit à l'import).
    """
    if pd.isna(level):
        return "low"
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 5:
        return "medium"
    return "low"


def _score_to_band(score: float) -> str:
    for low, high, label in RISK_BANDS:
        if low <= score < high:
            return label
    return "unknown"


def _to_int(value, default=0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def alert_to_netflow_row(raw: dict):
    """
    Reconstruit les 10 features NetFlow v1 (schéma modèle) depuis le champ
    `raw` d'une alerte normalisée (le _source OpenSearch complet). Retourne
    un dict des 10 colonnes, ou None si l'alerte ne porte pas de bloc flow
    exploitable (la ligne retombera alors sur level_to_band).
    """
    if not isinstance(raw, dict):
        return None
    data = raw.get("data")
    if not isinstance(data, dict):
        return None
    flow = data.get("flow")
    if not isinstance(flow, dict):
        return None

    # Compteurs : indexés en chaînes ("6278") -> int. Absents = non exploitable.
    for key in ("bytes_toserver", "bytes_toclient", "pkts_toserver", "pkts_toclient"):
        if flow.get(key) is None:
            return None
    in_bytes = _to_int(flow["bytes_toserver"], None)
    out_bytes = _to_int(flow["bytes_toclient"], None)
    in_pkts = _to_int(flow["pkts_toserver"], None)
    out_pkts = _to_int(flow["pkts_toclient"], None)
    if None in (in_bytes, out_bytes, in_pkts, out_pkts):
        return None

    protocol = PROTOCOL_NUMBERS.get(data.get("proto"))
    if protocol is None:
        return None

    src_port = _to_int(data.get("src_port") or flow.get("src_port"))
    dst_port = _to_int(data.get("dest_port") or flow.get("dest_port"))

    # TCP_FLAGS : absent des alertes indexées -> 0 (limite documentée).
    tcp_flags = 0
    tcp = data.get("tcp")
    if isinstance(tcp, dict) and tcp.get("tcp_flags"):
        try:
            tcp_flags = int(str(tcp["tcp_flags"]), 16)
        except ValueError:
            tcp_flags = 0

    # Durée : nécessite start ET end ; end absent des alertes indexées -> 0.
    duration_ms = 0
    start, end = flow.get("start"), flow.get("end")
    if start and end:
        try:
            duration_ms = int(
                (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds() * 1000
            )
            duration_ms = max(duration_ms, 0)
        except ValueError:
            duration_ms = 0

    l7 = float(L7_PROTO_BY_APP_PROTO.get(data.get("app_proto"), L7_PROTO_UNKNOWN))

    return {
        "L4_SRC_PORT": src_port,
        "L4_DST_PORT": dst_port,
        "PROTOCOL": int(protocol),
        "L7_PROTO": l7,
        "IN_BYTES": in_bytes,
        "OUT_BYTES": out_bytes,
        "IN_PKTS": in_pkts,
        "OUT_PKTS": out_pkts,
        "TCP_FLAGS": tcp_flags,
        "FLOW_DURATION_MILLISECONDS": duration_ms,
    }


def score_alerts(alerts_df: pd.DataFrame, base_dir: str = ".") -> dict:
    """
    Calcule la bande de risque des alertes live par le modèle flux-locaux,
    avec repli level_to_band par ligne. Retourne un dict :
      risk_band     : Series de bandes (alignée sur alerts_df.index)
      risk_score    : Series de scores 0-1 (NaN pour les lignes en repli)
      predicted_tactic : Series (None hors attaque / repli)
      band_source   : Series "model" | "fallback"
      meta          : {method, reason, n_total, n_model, n_fallback}
    """
    n = len(alerts_df)
    levels = alerts_df["rule_level"] if "rule_level" in alerts_df.columns else pd.Series(index=alerts_df.index)
    fallback_bands = levels.apply(level_to_band)

    result = {
        "risk_band": fallback_bands.copy(),
        "risk_score": pd.Series(np.nan, index=alerts_df.index, dtype=float),
        "predicted_tactic": pd.Series([None] * n, index=alerts_df.index, dtype=object),
        "band_source": pd.Series(["fallback"] * n, index=alerts_df.index, dtype=object),
        "meta": {"method": "fallback", "reason": "", "n_total": n, "n_model": 0, "n_fallback": n},
    }

    # Import tardif : évite un coût de chargement si le modèle est absent.
    from analysis_engine import LocalFlowAnalysisEngine

    if not LocalFlowAnalysisEngine.is_available(base_dir):
        result["meta"]["reason"] = "modèle flux-locaux absent (lancer train_local_flow_model.py)"
        return result

    if "raw" not in alerts_df.columns:
        result["meta"]["reason"] = "champ 'raw' absent des alertes -- repli intégral"
        return result

    rows = {}
    for idx, raw in alerts_df["raw"].items():
        row = alert_to_netflow_row(raw)
        if row is not None:
            rows[idx] = row

    if not rows:
        result["meta"]["reason"] = "aucune alerte ne porte de bloc flow exploitable -- repli intégral"
        return result

    feat = pd.DataFrame.from_dict(rows, orient="index")[LOCAL_FLOW_FEATURE_COLUMNS]
    try:
        validate_local_flow_schema(feat, context="live_flow_scoring.score_alerts")
    except FeatureSchemaError as exc:
        result["meta"]["reason"] = f"schéma invalide -- repli intégral ({exc})"
        return result

    engine = LocalFlowAnalysisEngine(
        binary_model_path=os.path.join(base_dir, "data/netflow/netflow_local_xgboost_binary.json"),
        multiclass_model_path=os.path.join(base_dir, "data/netflow/netflow_local_xgboost_multiclass.json"),
        classes_path=os.path.join(base_dir, "data/netflow/netflow_local_classes.pkl"),
    )
    out = engine.analyze(feat)

    result["risk_band"].loc[out.index] = out["risk_band"].values
    result["risk_score"].loc[out.index] = out["risk_score"].values
    result["predicted_tactic"].loc[out.index] = out["predicted_tactic"].values
    result["band_source"].loc[out.index] = "model"
    result["meta"] = {
        "method": "model+fallback",
        "reason": "TCP_FLAGS et FLOW_DURATION forcés à 0 (absents des alertes indexées) "
                  "-- impact ~1,1 % de l'importance du modèle binaire",
        "n_total": n,
        "n_model": len(rows),
        "n_fallback": n - len(rows),
    }
    return result
