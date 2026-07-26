"""
collector.py

Collecte incrémentale des alertes Wazuh/Suricata depuis l'Indexer.
- Se souvient du dernier timestamp traité (checkpoint local)
- Récupère uniquement les nouvelles alertes
- Normalise et stocke en JSON Lines (append-only)
"""

import os
import json
import logging
from datetime import datetime, timezone

from wazuh_client import WazuhIndexerClient
from normalizer import normalize_batch

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("collector")

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
OUTPUT_FILE = os.path.join(DATA_DIR, "alerts.jsonl")
CHECKPOINT_FILE = os.path.join(DATA_DIR, "checkpoint.txt")

BATCH_SIZE = 500  # alertes max par appel API


def load_checkpoint() -> str | None:
    """Retourne le dernier timestamp traité, ou None si première exécution."""
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, "r") as f:
            return f.read().strip()
    return None


def save_checkpoint(timestamp: str) -> None:
    """Sauvegarde le dernier timestamp traité."""
    with open(CHECKPOINT_FILE, "w") as f:
        f.write(timestamp)


def build_query(since: str | None) -> dict:
    """Construit la requête OpenSearch : tout depuis `since`, triée par timestamp croissant."""
    query = {
        "size": BATCH_SIZE,
        "sort": [{"@timestamp": {"order": "asc"}}],
    }
    if since:
        query["query"] = {
            "range": {
                "@timestamp": {"gt": since}
            }
        }
    return query


def append_to_jsonl(events: list) -> None:
    """Ajoute les événements normalisés au fichier JSON Lines."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


def run_collection() -> int:
    """Exécute un cycle complet de collecte. Retourne le nombre d'alertes collectées."""
    client = WazuhIndexerClient()
    since = load_checkpoint()

    logger.info("Collecte depuis : %s", since or "début (première exécution)")

    query = build_query(since)
    result = client.search_alerts(query=query)
    hits = result["hits"]["hits"]

    if not hits:
        logger.info("Aucune nouvelle alerte.")
        return 0

    normalized = normalize_batch(hits)
    append_to_jsonl(normalized)

    last_timestamp = normalized[-1]["timestamp"]
    save_checkpoint(last_timestamp)

    logger.info("%d alertes collectées et stockées. Nouveau checkpoint : %s",
                len(normalized), last_timestamp)
    return len(normalized)


if __name__ == "__main__":
    count = run_collection()
    print(f"\nCollecte terminée : {count} alertes ajoutées à {OUTPUT_FILE}")
