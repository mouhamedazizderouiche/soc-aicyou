"""
normalizer.py

Transforme les alertes brutes Wazuh/Suricata (JSON hétérogène) en un
schéma commun structuré, prêt pour l'extraction de features (Phase 3).
"""

import logging

logger = logging.getLogger("normalizer")


def _detect_source_type(source: dict) -> str:
    """Déduit la source réelle de l'événement à partir de sa structure."""
    decoder_name = source.get("decoder", {}).get("name", "")
    rule_groups = source.get("rule", {}).get("groups", [])

    if "suricata" in rule_groups or decoder_name == "json" and "data" in source and "alert" in source.get("data", {}):
        return "suricata"
    if "sca" in rule_groups or decoder_name == "sca":
        return "sca"
    if decoder_name == "pam":
        return "pam"
    return "wazuh_generic"


def normalize_alert(raw_alert: dict) -> dict:
    """
    Convertit une alerte brute (document _source d'OpenSearch) en un
    dict normalisé, avec un schéma commun stable.
    """
    source = raw_alert  # on suppose que raw_alert = hit["_source"]

    rule = source.get("rule", {})
    data = source.get("data", {})
    agent = source.get("agent", {})

    source_type = _detect_source_type(source)

    normalized = {
        "timestamp": source.get("@timestamp") or source.get("timestamp"),
        "agent_name": agent.get("name"),
        "source_type": source_type,
        "event_type": data.get("event_type"),  # rempli surtout pour suricata
        "rule_id": rule.get("id"),
        "rule_description": rule.get("description"),
        "rule_level": rule.get("level"),
        "src_ip": data.get("src_ip") or data.get("srcip"),
        "dest_ip": data.get("dest_ip") or data.get("dstip"),
        "src_port": data.get("src_port"),
        "dest_port": data.get("dest_port"),
        "protocol": data.get("proto"),
        "direction": data.get("direction"),
        "flow_src_ip": data.get("flow", {}).get("src_ip") if isinstance(data.get("flow"), dict) else None,
        "flow_dest_ip": data.get("flow", {}).get("dest_ip") if isinstance(data.get("flow"), dict) else None,
        "mitre_tactics": rule.get("mitre_tactics"),
        "mitre_techniques": rule.get("mitre_techniques"),
        "raw": source,  # on ne perd jamais l'original
    }

    return normalized


def normalize_batch(raw_alerts: list) -> list:
    """Normalise une liste de hits OpenSearch (hits['hits'])."""
    normalized = []
    for hit in raw_alerts:
        try:
            normalized.append(normalize_alert(hit["_source"]))
        except Exception as e:
            logger.warning("Échec de normalisation pour un document (id=%s) : %s",
                            hit.get("_id", "inconnu"), e)
    return normalized


if __name__ == "__main__":
    from wazuh_client import WazuhIndexerClient
    import json

    client = WazuhIndexerClient()
    result = client.search_alerts(size=10)
    hits = result["hits"]["hits"]

    normalized = normalize_batch(hits)

    print(f"\n{len(normalized)} alertes normalisées.\n")
    for event in normalized[:3]:
        preview = {k: v for k, v in event.items() if k != "raw"}
        print(json.dumps(preview, indent=2, ensure_ascii=False))
        print("---")
