"""
playbook.py

Version structuree (machine-readable) de docs/playbook-reponse-incidents.md (v2).
Utilise par analysis_engine.py pour generer des recommandations ancrees dans la
procedure reelle -- sources de log, indicateurs, criteres d'escalade, actions
L1/L2 -- plutot qu'un texte generique deconnecte de tout document de reference.

Source de verite humaine : docs/playbook-reponse-incidents.md
Ce module doit rester synchronise avec ce document ; toute modification du
playbook.md doit etre repercutee ici (et vice-versa).

Note de transparence (voir Limites actuelles du systeme, playbook.md) : les
SLA ci-dessous sont des cibles documentees, PAS des engagements applicables.
Aucun mecanisme d'alerte (email/Slack/webhook) n'existe actuellement -- le
dashboard est en pull uniquement, donc le respect du SLA depend entierement
de la frequence de consultation par un analyste humain.
"""

from mitre_categories import TACTIC_MITRE_IDS

# SLA cibles (identiques pour toutes les tactiques, definis dans la section
# "Principe de triage" du playbook.md). Aspirationnels -- voir note ci-dessus.
SLA_TARGETS = {
    "critical": "15 min",
    "high": "24h ouvrees",
}
SLA_NOTE = (
    "cible non applicable automatiquement, aucun mecanisme d'alerte n'existe"
)

PLAYBOOKS = {
    "Impact": {
        "mitre_id": TACTIC_MITRE_IDS.get("Impact", "TA0040"),
        "techniques": ["T1498 (Network DoS)", "T1499 (Endpoint DoS)"],
        "log_sources": [
            "Suricata eve.json (event_type=alert, flow)",
            "Alertes Wazuh agregees",
            "Metriques systeme (charge CPU/reseau)",
        ],
        "key_indicators": (
            "Pic de volume de connexions, unique_dest_ports/event_count eleves "
            "sur fenetre courte (1 min), alerte Suricata QUIC/flood"
        ),
        "escalation_criteria": (
            "Service indisponible confirme, OU volume >3x la baseline habituelle, "
            "OU alerte critical avec confiance modele >90%"
        ),
        "l1_actions": [
            "Confirmer l'impact reel (curl/healthcheck sur le service cible)",
            "Identifier la/les IP(s) source(s) via le mitre_id TA0040",
            "Verifier whois/reverse DNS avant toute action (eviter de bloquer un service legitime -- CDN, load balancer)",
            "Documenter (horodatage, IP, volume observe)",
        ],
        "l2_actions": [
            "Si trafic externe illegitime confirme : bloquer temporairement via UFW (ufw deny from <IP>)",
            "Si le trafic persiste apres blocage (IP spoofee / botnet distribue) : escalader vers l'equipe reseau",
            "Post-incident : evaluer si un rate-limiting permanent est justifie",
        ],
        "validation_status": "untested",
        "limitations": (
            "Playbook JAMAIS valide contre une attaque DoS reelle (contrairement a "
            "Reconnaissance et InitialAccess_CredentialAccess) -- traiter les recommandations "
            "ci-dessous avec prudence accrue jusqu'a validation live (scenario 3, en attente)."
        ),
    },
    "Reconnaissance": {
        "mitre_id": TACTIC_MITRE_IDS.get("Reconnaissance", "TA0043"),
        "techniques": ["T1595 (Active Scanning)"],
        "log_sources": [
            "Regles Suricata custom sid 9000001/9000002 (docker/suricata/config/rules/local.rules)",
            "feature_extractor.py (inbound_unique_ports, fenetre 1 min)",
        ],
        "key_indicators": (
            "Une meme source (flow_src_ip) contacte de nombreux ports distincts en peu "
            "de temps ; alerte 'CUSTOM Possible port scan detected'"
        ),
        "escalation_criteria": (
            "Source externe non identifiee, OU scan suivi d'une tentative de connexion "
            "applicative dans les heures suivantes (correlation)"
        ),
        "l1_actions": [
            "Identifier la source reelle via flow_src_ip (pas src_ip)",
            "Verifier si la source est un outil d'audit interne autorise",
            "Documenter la source pour correlation future (ne pas bloquer un scan seul sans confirmation)",
        ],
        "l2_actions": [
            "Si source interne non autorisee : contacter le proprietaire de la machine (poste potentiellement compromis)",
            "Si source externe : surveillance renforcee 24-48h, correler avec toute tentative d'authentification ulterieure de la meme IP",
            "Un scan seul n'est pas une compromission -- ne pas escalader en incident critique sans signal complementaire",
        ],
        "validation_status": "validated",
        "limitations": None,
    },
    "InitialAccess_CredentialAccess": {
        "mitre_id": TACTIC_MITRE_IDS.get("InitialAccess_CredentialAccess", "TA0001/TA0006"),
        "techniques": ["T1110 (Brute Force)", "T1078 (Valid Accounts)"],
        "log_sources": [
            "Regles Wazuh natives (5760, 5503, 5715) + regles custom 100010/100011",
            "docker/wazuh-docker/single-node/config/wazuh_cluster/custom_rules/local_rules.xml",
            "journalctl -u ssh",
        ],
        "key_indicators": (
            "Echecs d'authentification repetes depuis une meme source (regle 100010) ; "
            "succes apres une serie d'echecs (regle 100011, niveau 14 -- signal le plus critique)"
        ),
        "escalation_criteria": (
            "Regle 100011 declenchee (succes apres echecs) -> escalade immediate et "
            "automatique, quel que soit le contexte"
        ),
        "l1_actions": [
            "Verifier les journaux d'authentification du systeme cible",
            "Confirmer si une authentification a reussi apres la sequence d'echecs",
            "Identifier le compte concerne et son niveau de privilege",
        ],
        "l2_actions": [
            "Si compromission confirmee (regle 100011) : forcer la rotation immediate des identifiants",
            "Si echecs seuls (regle 100010) : envisager un verrouillage temporaire du compte ou rate-limiting SSH",
            "Documenter la methode (brute-force simple vs. credential stuffing)",
            "Verifier si le compte compromis a ete utilise pour du mouvement lateral",
        ],
        "validation_status": "validated",
        "limitations": (
            "La regle native Wazuh 5710 ne s'est pas declenchee sur une attaque courte "
            "(sous son seuil par defaut) -- les regles custom 100010/100011 sont la "
            "source de verite prioritaire pour cette tactique, pas les regles natives seules."
        ),
    },
    "PrivilegeEscalation": {
        "mitre_id": TACTIC_MITRE_IDS.get("PrivilegeEscalation", "TA0004"),
        "techniques": [
            "T1548 (Abuse Elevation Control Mechanism)",
            "T1068 (Exploitation for Privilege Escalation)",
        ],
        "log_sources": [
            "Wazuh : modifications /etc/passwd, /etc/sudoers",
            "Execution de binaires SUID inhabituels, taches cron",
        ],
        "key_indicators": (
            "Modification de permissions, nouveau compte a privileges, processus "
            "inhabituel execute avec elevation"
        ),
        "escalation_criteria": "Systematique -- voir limite du modele ci-dessous",
        "l1_actions": [
            "Traiter comme prioritaire independamment du score de confiance affiche",
            "Verifier l'integrite du systeme : processus en cours, modifications recentes de /etc/passwd ou /etc/sudoers, taches cron",
        ],
        "l2_actions": [
            "Isoler la machine du reseau si compromission confirmee, avant investigation approfondie",
            "Conserver une image/snapshot du systeme avant toute remediation (preuve forensique)",
            "Verifier l'integrite de l'ensemble de la chaine de privileges (comptes crees, groupes modifies)",
        ],
        "validation_status": "weak_model",
        "limitations": (
            "Le classifieur de tactique a la precision la plus faible sur cette categorie "
            "(F1 = 0.19, precision = 0.13 -- 52 exemples d'entrainement reels seulement, "
            "meme apres SMOTE modere x57). Le score de confiance ne doit PAS etre le seul "
            "filtre de decision pour cette tactique -- toute alerte doit etre traitee en "
            "priorite manuelle systematique, meme a faible confiance."
        ),
    },
}


def build_recommendation(
    risk_band: str,
    tactic: str,
    confidence: float,
    detected_by_anomaly: bool = False,
) -> str:
    """
    Construit une recommandation textuelle ancree dans le playbook reel pour
    une alerte donnee, plutot qu'un texte generique fixe par (band, tactic).

    Deux alertes de meme (risk_band, tactic) peuvent produire un texte
    different si leurs signaux sous-jacents different (confiance du modele,
    detection par Isolation Forest seul vs. signature XGBoost connue).

    Important : detected_by_anomaly est verifie AVANT le court-circuit
    low/medium. Une alerte captee uniquement par Isolation Forest a, par
    construction, un score XGBoost bas (c'est la raison meme pour laquelle
    IF a du la rattraper) -- donc elle tombe presque toujours en bande
    low/medium. Ignorer detected_by_anomaly a ce stade aurait masque le
    signal la ou il compte le plus.
    """
    playbook = PLAYBOOKS.get(tactic)
    if playbook is None:
        return "Surveillance de routine -- aucune action immediate requise."

    anomaly_note = None
    if detected_by_anomaly:
        anomaly_note = (
            "Detecte uniquement par le detecteur d'anomalies (Isolation Forest), sans "
            "signature XGBoost connue -- le score de risque affiche (base sur XGBoost) "
            "est donc probablement bas malgre ce signal. Traiter avec un biais de "
            "verification renforce : l'absence de signature connue ne signifie pas "
            "absence de risque."
        )

    if risk_band in ("low", "medium"):
        base = (
            f"Bande '{risk_band}' pour la tactique {tactic} ({playbook['mitre_id']})."
        )
        if anomaly_note:
            base += (
                " Verification L1 recommandee malgre la bande de risque basse : "
                + anomaly_note
            )
        else:
            base += (
                " Surveillance passive suffisante. Aucune action L1/L2 requise a ce "
                "stade ; reevaluer si le score augmente ou si un signal complementaire "
                "apparait."
            )
        return base

    parts = []

    if risk_band == "critical":
        parts.append(
            f"CRITIQUE ({playbook['mitre_id']}, {tactic}) -- SLA {SLA_TARGETS['critical']} "
            f"({SLA_NOTE}). Critere d'escalade : {playbook['escalation_criteria']}."
        )
        parts.append("Actions L1 : " + "; ".join(playbook["l1_actions"]) + ".")
        parts.append("Actions L2 / confinement : " + "; ".join(playbook["l2_actions"]) + ".")
    else:  # high
        parts.append(
            f"ELEVE ({playbook['mitre_id']}, {tactic}) -- SLA {SLA_TARGETS['high']} "
            f"({SLA_NOTE})."
        )
        parts.append("Actions L1 : " + "; ".join(playbook["l1_actions"]) + ".")

    parts.append(f"Confiance du modele de tactique : {confidence:.0%}.")

    if anomaly_note:
        parts.append(anomaly_note)

    if confidence < 0.5:
        parts.append(
            "Confiance de classification de tactique faible -- la tactique predite doit "
            "etre verifiee manuellement avant d'orienter la reponse."
        )

    if playbook["limitations"]:
        parts.append(f"Limite connue : {playbook['limitations']}")

    return " ".join(parts)
