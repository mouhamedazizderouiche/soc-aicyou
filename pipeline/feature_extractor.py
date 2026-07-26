"""
feature_extractor.py

Transforme le flux d'alertes normalisées en features comportementales
agrégées par agent et par fenêtre temporelle (5 minutes par défaut).
Ces features serviront d'entrée au modèle de détection (Phase 3).
"""

import json
import logging
from datetime import datetime
from collections import defaultdict

import pandas as pd

logger = logging.getLogger("feature_extractor")

WINDOW_MINUTES = 5


def load_alerts(jsonl_path: str) -> list:
    """Charge les alertes normalisées depuis le fichier JSON Lines."""
    alerts = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            alerts.append(json.loads(line))
    return alerts


def _parse_timestamp(ts: str) -> datetime:
    """Parse un timestamp ISO 8601 (format Wazuh/OpenSearch)."""
    # Format typique : 2026-07-26T08:28:53.439Z
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _window_key(dt: datetime) -> datetime:
    """Arrondit un timestamp au début de sa fenêtre de WINDOW_MINUTES."""
    minute_bucket = (dt.minute // WINDOW_MINUTES) * WINDOW_MINUTES
    return dt.replace(minute=minute_bucket, second=0, microsecond=0)


def extract_features(alerts: list) -> pd.DataFrame:
    """
    Agrège les alertes par (agent, fenêtre temporelle) et calcule les
    features comportementales.
    """
    groups = defaultdict(list)

    for alert in alerts:
        if not alert.get("timestamp") or not alert.get("agent_name"):
            continue
        dt = _parse_timestamp(alert["timestamp"])
        window = _window_key(dt)
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

        row = {
            "agent_name": agent_name,
            "window_start": window,
            "event_count": len(group_alerts),
            "unique_dest_ips": len(dest_ips),
            "unique_dest_ports": len(dest_ports),
            "distinct_rule_ids": len(rule_ids),
            "avg_rule_level": sum(levels) / len(levels) if levels else 0,
            "max_rule_level": max(levels) if levels else 0,
            "suricata_ratio": suricata_count / len(group_alerts) if group_alerts else 0,
            "time_span_seconds": (max(timestamps) - min(timestamps)).total_seconds()
                                  if len(timestamps) > 1 else 0,
        }
        rows.append(row)

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values("window_start").reset_index(drop=True)
    return df


if __name__ == "__main__":
    import os

    data_path = os.path.join(os.path.dirname(__file__), "data", "alerts.jsonl")
    alerts = load_alerts(data_path)
    logger.info("Chargé %d alertes brutes.", len(alerts))

    features_df = extract_features(alerts)
    logger.info("%d fenêtres comportementales générées.", len(features_df))

    print(f"\n{len(features_df)} lignes de features (agent x fenêtre 5min)\n")
    print(features_df.head(10).to_string(index=False))
    print(f"\nStatistiques descriptives :\n")
    print(features_df.describe().to_string())

    output_path = os.path.join(os.path.dirname(__file__), "data", "features.csv")
    features_df.to_csv(output_path, index=False)
    print(f"\nFeatures sauvegardées dans {output_path}")
