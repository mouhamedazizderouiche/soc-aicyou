"""
wazuh_client.py

Client d'authentification et de requêtes vers l'API REST Wazuh.
Gère l'obtention du token JWT et son renouvellement.
"""

import os
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()


class WazuhClient:
    """Client minimal pour interagir avec l'API REST Wazuh."""

    def __init__(self):
        self.base_url = os.getenv("WAZUH_API_URL")
        self.user = os.getenv("WAZUH_API_USER")
        self.password = os.getenv("WAZUH_API_PASSWORD")

        if not all([self.base_url, self.user, self.password]):
            raise ValueError(
                "Variables d'environnement manquantes. "
                "Vérifie que WAZUH_API_URL, WAZUH_API_USER et "
                "WAZUH_API_PASSWORD sont définies dans .env"
            )

        self.token = None

    def authenticate(self) -> str:
        """Authentifie auprès de l'API et récupère un token JWT."""
        url = f"{self.base_url}/security/user/authenticate"
        response = requests.post(
            url,
            auth=(self.user, self.password),
            verify=False,
            timeout=10,
        )
        response.raise_for_status()
        self.token = response.json()["data"]["token"]
        return self.token

    def _headers(self) -> dict:
        if not self.token:
            self.authenticate()
        return {"Authorization": f"Bearer {self.token}"}

    def get(self, endpoint: str, params: dict = None) -> dict:
        """Effectue une requête GET authentifiée vers l'API Wazuh."""
        url = f"{self.base_url}{endpoint}"
        response = requests.get(
            url,
            headers=self._headers(),
            params=params or {},
            verify=False,
            timeout=10,
        )

        if response.status_code == 401:
            self.authenticate()
            response = requests.get(
                url,
                headers=self._headers(),
                params=params or {},
                verify=False,
                timeout=10,
            )

        response.raise_for_status()
        return response.json()


if __name__ == "__main__":
    client = WazuhClient()
    token = client.authenticate()
    print(f"Authentification réussie. Token (tronqué) : {token[:30]}...")

    info = client.get("/")
    print(f"Info API Wazuh : {info['data']['title']} v{info['data']['api_version']}")
