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

Historique (14/08/2026) : la table ne couvrait initialement que les 22
types d'attaque présents dans KDDTrain+. Le jeu de test NSL-KDD est
délibérément conçu pour inclure des types d'attaque absents de
l'entraînement (test de généralisation) -- 17 types supplémentaires
(29.2% des échantillons d'attaque du test set) n'avaient donc aucune
tactique associée et étaient silencieusement exclus de l'évaluation du
classifieur (build_tactic_dataset() dans tactic_classifier.py filtre les
labels "Unknown"). Toute prédiction du modèle sur ces types en production
n'avait donc jamais été comparée à une vérité terrain. Extension ci-dessous
basée sur la taxonomie standard NSL-KDD (DoS/Probe/R2L/U2R -> Impact/
Reconnaissance/InitialAccess_CredentialAccess/PrivilegeEscalation).

Trois types sont ambigus dans la littérature NSL-KDD et ont fait l'objet
d'un choix explicite plutôt que d'une classification automatique :
- "worm" : classé DoS par certaines sources, R2L par d'autres -> retenu
  Impact (majorité des sources, comportement de propagation/déni observé)
- "ps", "xterm" : U2R dans la taxonomie standard, mais aussi lisibles comme
  abus de privilège local au sens strict -> retenus PrivilegeEscalation
  (cohérent avec le reste des U2R, pas de raison de les traiter à part)
"""

TACTIC_GROUPS = {
    # DoS -> Impact
    "back": "Impact",
    "land": "Impact",
    "neptune": "Impact",
    "pod": "Impact",
    "smurf": "Impact",
    "teardrop": "Impact",
    "apache2": "Impact",
    "mailbomb": "Impact",
    "processtable": "Impact",
    "udpstorm": "Impact",
    "worm": "Impact",  # ambigu, voir note d'en-tête

    # Probe -> Reconnaissance
    "ipsweep": "Reconnaissance",
    "nmap": "Reconnaissance",
    "portsweep": "Reconnaissance",
    "satan": "Reconnaissance",
    "mscan": "Reconnaissance",
    "saint": "Reconnaissance",

    # R2L -> Initial Access / Credential Access (regroupés : peu d'exemples individuellement)
    "ftp_write": "InitialAccess_CredentialAccess",
    "guess_passwd": "InitialAccess_CredentialAccess",
    "imap": "InitialAccess_CredentialAccess",
    "multihop": "InitialAccess_CredentialAccess",
    "phf": "InitialAccess_CredentialAccess",
    "spy": "InitialAccess_CredentialAccess",
    "warezclient": "InitialAccess_CredentialAccess",
    "warezmaster": "InitialAccess_CredentialAccess",
    "httptunnel": "InitialAccess_CredentialAccess",
    "named": "InitialAccess_CredentialAccess",
    "sendmail": "InitialAccess_CredentialAccess",
    "snmpgetattack": "InitialAccess_CredentialAccess",
    "snmpguess": "InitialAccess_CredentialAccess",
    "xlock": "InitialAccess_CredentialAccess",
    "xsnoop": "InitialAccess_CredentialAccess",

    # U2R -> Privilege Escalation
    "buffer_overflow": "PrivilegeEscalation",
    "loadmodule": "PrivilegeEscalation",
    "perl": "PrivilegeEscalation",
    "rootkit": "PrivilegeEscalation",
    "sqlattack": "PrivilegeEscalation",
    "ps": "PrivilegeEscalation",  # ambigu, voir note d'en-tête
    "xterm": "PrivilegeEscalation",  # ambigu, voir note d'en-tête
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
    print(f"\nTotal des types d'attaque couverts : {len(TACTIC_GROUPS)}")
