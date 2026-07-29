"""
feature_extractor.py

Transforme le flux d'alertes normalisées en features comportementales
agrégées par agent et par fenêtre temporelle.

Approche multi-échelle (comme dans les systèmes de détection
professionnels) : une fenêtre COURTE (1 min) capture les rafales de
scan/attaque rapide, une fenêtre LONGUE (5 min) capture les tendances
comportementales générales. Un scan de quelques dizaines de secondes
peut être noyé dans une fenêtre de 5 min mais reste net dans une
fenêtre de 1 min.

Distingue le trafic ENTRANT (la machine surveillée est la cible d'une
connexion initiée par un tiers -> signal de reconnaissance/scan) du
trafic SORTANT (la machine surveillée initie la connexion -> navigation
normale), basé sur flow.src_ip / flow.dest_ip (initiateur réel du flux).

Limite connue : Wazuh n'indexe que les événements Suricata de type
"alert" (pas "flow" bruts) -- donc les features entrantes ne peuvent
être calculées que sur du trafic ayant déjà déclenché au moins une
règle Suricata (native ou custom). Les règles custom de la Couche 2
(voir docker/suricata/config/rules/local.rules) sont donc un
prérequis pour que ces features fonctionnent sur du trafic qui ne
matche aucune signature native.
"""

import os
import json
import logging
from datetime import datetime
from collections import defaultdict

import pandas as pd
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("feature_extractor")

MONITORED_HOST_IP = os.getenv("MONITORED_HOST_IP")

if not MONITORED_HOST_IP:
    logger.warning(
        "MONITORED_HOST_IP non définie dans .env — les features "
        "entrant/sortant ne pourront pas être calculées correctement."
    )


def load_alerts(jsonl_path: str) -> list:
    """Charge les alertes normalisées depuis le fichier JSON Lines."""
    alerts = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            alerts.append(json.loads(line))
    return alerts


def _parse_timestamp(ts: str) -> datetime:
    """Parse un timestamp ISO 8601 (format Wazuh/OpenSearch)."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _window_key(dt: datetime, window_minutes: int) -> datetime:
    """Arrondit un timestamp au début de sa fenêtre de window_minutes."""
    if window_minutes >= 1:
        minute_bucket = (dt.minute // window_minutes) * window_minutes
        return dt.replace(minute=minute_bucket, second=0, microsecond=0)
    # Support fenêtres sous la minute (ex: 0.5 = 30s), pas utilisé par défaut
    return dt.replace(microsecond=0)


def _is_inbound(alert: dict) -> bool:
    """ENTRANT = flux initié par un tiers vers la machine surveillée."""
    return MONITORED_HOST_IP is not None and alert.get("flow_dest_ip") == MONITORED_HOST_IP


def _is_outbound(alert: dict) -> bool:
    """SORTANT = flux initié par la machine surveillée elle-même."""
    return MONITORED_HOST_IP is not None and alert.get("flow_src_ip") == MONITORED_HOST_IP


def extract_features(alerts: list, window_minutes: int = 5) -> pd.DataFrame:
    """
    Agrège les alertes par (agent, fenêtre temporelle) et calcule les
    features comportementales.

    window_minutes : taille de la fenêtre d'agrégation. Utiliser une
    valeur courte (1) pour la détection de rafales/scans, une valeur
    plus longue (5-15) pour l'analyse de tendance générale.
    """
    groups = defaultdict(list)

    for alert in alerts:
        if not alert.get("timestamp") or not alert.get("agent_name"):
            continue
        dt = _parse_timestamp(alert["timestamp"])
        window = _window_key(dt, window_minutes)
        key = (alert["agent_name"], window)
        groups[key].append(alert)

    rows = []
    for (agent_name, window), group_alerts in groups.items():
        dest_ips = {a["dest_ip"] for a in group_alerts if a.get("dest_ip")}
        dest_ports = {a["dest_port"] for a in group_alerts if a.get("dest_port")}
        rule_ids = {a["rule_id"] for a in group_alerts if a.get("rule_id")}
        levels = [a["rule_level"] for a in group_alerts if a.get("rule_level") is not None]
        timestamps = [_parse_timestamp(a["timestamp"]) for a in group_alerts]
        suricata_count = sum(1 for a in group_alerts if a["source_type"] == "suricata")

        inbound_alerts = [a for a in group_alerts if _is_inbound(a)]
        outbound_alerts = [a for a in group_alerts if _is_outbound(a)]

        inbound_src_ips = {a["flow_src_ip"] for a in inbound_alerts if a.get("flow_src_ip")}
        inbound_dest_ports = {a["dest_port"] for a in inbound_alerts if a.get("dest_port")}
        outbound_dest_ports = {a["dest_port"] for a in outbound_alerts if a.get("dest_port")}

        row = {
            "agent_name": agent_name,
            "window_start": window,
            "window_minutes": window_minutes,
            "event_count": len(group_alerts),
            "unique_dest_ips": len(dest_ips),
            "unique_dest_ports": len(dest_ports),
            "distinct_rule_ids": len(rule_ids),
            "avg_rule_level": sum(levels) / len(levels) if levels else 0,
            "max_rule_level": max(levels) if levels else 0,
            "suricata_ratio": suricata_count / len(group_alerts) if group_alerts else 0,
            "time_span_seconds": (max(timestamps) - min(timestamps)).total_seconds()
                                  if len(timestamps) > 1 else 0,
            "inbound_event_count": len(inbound_alerts),
            "inbound_unique_src_ips": len(inbound_src_ips),
            "inbound_unique_ports": len(inbound_dest_ports),
            "outbound_event_count": len(outbound_alerts),
            "outbound_unique_ports": len(outbound_dest_ports),
        }
        rows.append(row)

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values("window_start").reset_index(drop=True)
    return df


if __name__ == "__main__":
    data_path = os.path.join(os.path.dirname(__file__), "data", "alerts.jsonl")
    alerts = load_alerts(data_path)
    logger.info("Chargé %d alertes brutes.", len(alerts))

    cols_to_show = [
        "agent_name", "window_start", "event_count",
        "inbound_event_count", "inbound_unique_src_ips", "inbound_unique_ports",
        "outbound_event_count", "outbound_unique_ports",
    ]

    # --- Fenêtre courte : détection de rafales/scans ---
    print("=" * 70)
    print("FENÊTRE COURTE (1 min) — détection de rafales/scans")
    print("=" * 70)
    features_1min = extract_features(alerts, window_minutes=1)
    scan_activity = features_1min[features_1min["inbound_event_count"] > 0]
    print(f"\n{len(scan_activity)} fenêtres avec activité entrante détectée :\n")
    print(scan_activity[cols_to_show].to_string(index=False))

    features_1min.to_csv(
        os.path.join(os.path.dirname(__file__), "data", "features_1min.csv"), index=False
    )

    # --- Fenêtre longue : tendance comportementale générale ---
    print("\n" + "=" * 70)
    print("FENÊTRE LONGUE (5 min) — tendance comportementale générale")
    print("=" * 70)
    features_5min = extract_features(alerts, window_minutes=5)
    print(f"\n{len(features_5min)} fenêtres générées au total.")

    features_5min.to_csv(
        os.path.join(os.path.dirname(__file__), "data", "features.csv"), index=False
    )

    print(f"\nFeatures sauvegardées : data/features_1min.csv et data/features.csv")
