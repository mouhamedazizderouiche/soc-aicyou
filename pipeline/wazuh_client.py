"""
wazuh_client.py

Client de lecture des alertes Wazuh depuis l'Indexer (OpenSearch).
Utilise un compte de service dédié en lecture seule (pipeline_svc),
restreint à l'index wazuh-alerts-* (principe du moindre privilège).
"""

import os
import logging
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("wazuh_client")


class WazuhIndexerClient:
    """Client minimal pour interroger l'index wazuh-alerts-* sur l'Indexer."""

    def __init__(self):
        self.base_url = os.getenv("WAZUH_INDEXER_URL")
        self.user = os.getenv("WAZUH_INDEXER_USER")
        self.password = os.getenv("WAZUH_INDEXER_PASSWORD")

        if not all([self.base_url, self.user, self.password]):
            raise ValueError(
                "Variables d'environnement manquantes. "
                "Vérifie WAZUH_INDEXER_URL, WAZUH_INDEXER_USER et "
                "WAZUH_INDEXER_PASSWORD dans .env"
            )

        self._auth = (self.user, self.password)

    def search_alerts(self, query: dict = None, size: int = 100) -> dict:
        """
        Recherche des alertes dans wazuh-alerts-*.

        query : requête OpenSearch DSL (dict). Si None, retourne les
                dernières alertes triées par timestamp décroissant.
        size  : nombre max de résultats.
        """
        url = f"{self.base_url}/wazuh-alerts-*/_search"

        body = query or {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        response = requests.get(
            url,
            auth=self._auth,
            json=body,
            verify=False,
            timeout=15,
        )
        response.raise_for_status()
        return response.json()


if __name__ == "__main__":
    client = WazuhIndexerClient()
    logger.info("Connexion à l'Indexer Wazuh...")

    result = client.search_alerts(size=5)
    total = result["hits"]["total"]["value"]
    logger.info("Connexion réussie. %d alertes disponibles au total.", total)

    print(f"\n{total} alertes trouvées. Aperçu des 5 dernières :\n")
    for hit in result["hits"]["hits"]:
        source = hit["_source"]
        rule_desc = source.get("rule", {}).get("description", "N/A")
        agent = source.get("agent", {}).get("name", "N/A")
        timestamp = source.get("@timestamp", "N/A")
        print(f"[{timestamp}] agent={agent} | {rule_desc}")
