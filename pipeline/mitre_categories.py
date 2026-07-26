"""
mitre_categories.py

Regroupement des labels d'attaque NSL-KDD en catégories de tactiques
MITRE ATT&CK, utilisé UNIQUEMENT pour construire les données
d'entraînement du modèle multi-classe (tactic_classifier.py).

Une fois entraîné, le modèle ne fait plus de lookup par label — il
prédit la tactique directement à partir du comportement réseau observé.

Regroupement par catégorie plutôt que par type individuel : certains
types d'attaque ont trop peu d'exemples (ex: spy, land) pour être
appris isolément par un modèle multi-classe.
"""

TACTIC_GROUPS = {
    # DoS -> Impact
    "back": "Impact",
    "land": "Impact",
    "neptune": "Impact",
    "pod": "Impact",
    "smurf": "Impact",
    "teardrop": "Impact",

    # Probe -> Reconnaissance
    "ipsweep": "Reconnaissance",
    "nmap": "Reconnaissance",
    "portsweep": "Reconnaissance",
    "satan": "Reconnaissance",

    # R2L -> Initial Access / Credential Access (regroupés : peu d'exemples individuellement)
    "ftp_write": "InitialAccess_CredentialAccess",
    "guess_passwd": "InitialAccess_CredentialAccess",
    "imap": "InitialAccess_CredentialAccess",
    "multihop": "InitialAccess_CredentialAccess",
    "phf": "InitialAccess_CredentialAccess",
    "spy": "InitialAccess_CredentialAccess",
    "warezclient": "InitialAccess_CredentialAccess",
    "warezmaster": "InitialAccess_CredentialAccess",

    # U2R -> Privilege Escalation
    "buffer_overflow": "PrivilegeEscalation",
    "loadmodule": "PrivilegeEscalation",
    "perl": "PrivilegeEscalation",
    "rootkit": "PrivilegeEscalation",
}

TACTIC_MITRE_IDS = {
    "Impact": "TA0040",
    "Reconnaissance": "TA0043",
    "InitialAccess_CredentialAccess": "TA0001/TA0006",
    "PrivilegeEscalation": "TA0004",
}


def label_to_tactic(label: str) -> str:
    """Retourne la catégorie de tactique pour un label d'attaque donné."""
    return TACTIC_GROUPS.get(label, "Unknown")


if __name__ == "__main__":
    from collections import Counter
    print("Distribution des catégories définies :")
    print(Counter(TACTIC_GROUPS.values()))
