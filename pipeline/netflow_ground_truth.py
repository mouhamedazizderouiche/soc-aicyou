"""
netflow_ground_truth.py

Vérité terrain du trafic réel capturé sur la VM, utilisée pour le test de
transfert inter-domaine (voir netflow_transfer_test.py). Chaque fenêtre
étiquetée ci-dessous est justifiée par une source EXTERNE aux features
elles-mêmes -- journal de bord, journal système, ou plan d'expérience --
jamais par la signature réseau que le modèle est censé apprendre. Étiqueter
un flux « scan » parce qu'il porte le drapeau SYN seul rendrait le test
circulaire et sans valeur.

HÔTES
-----
192.168.1.249  VM surveillée (cible). Adresse actuelle.
192.168.1.112  MÊME VM, bail DHCP antérieur (jusqu'à début août 2026).
               Confirmé : le scan du 28/07 vise .112, celui du 31/08 vise
               .249, et aucune des deux adresses n'est active en même
               temps que l'autre. À noter : pipeline/.env déclare encore
               MONITORED_HOST_IP=192.168.1.112, donc obsolète.
192.168.1.225  VM Windows d'attaque (scans nmap, floods TCP).
192.168.1.230  Seconde source de flood (session du 15/08).
192.168.1.159  Poste ayant exécuté la force brute SSH (Posh-SSH).

SOURCES DE VÉRITÉ
-----------------
Force brute SSH : /var/log/auth.log* — 48 lignes « Failed password for
  bftest from 192.168.1.159 » réparties sur quatre fenêtres. C'est le
  système cible lui-même qui atteste l'attaque, indépendamment de
  Suricata. Attention : auth.log est horodaté en +01:00, eve.json en
  +0000 ; les fenêtres ci-dessous sont en UTC, converties.
Floods TCP      : docs/journal-technique.md, entrée du 15/08 — « Flood TCP
  de 300 connexions (PowerShell, VM Windows -> VM cible, port 22) ».
  Quatre rafales de 300 flux exactement, ce qui correspond au plan
  d'expérience (300 connexions), sur une minute chacune.
Scans nmap      : docs/journal-technique.md (sessions de simulation) —
  confirmés par le nombre de ports de destination distincts (997 et 1004
  sur les deux campagnes, soit la liste « top 1000 ports » de nmap), une
  caractéristique de l'OUTIL et non du trafic.

FENÊTRES BÉNIGNES
-----------------
Choisies parmi les périodes sans aucune activité d'attaque connue et sans
implication des hôtes attaquants. Tout flux impliquant une IP attaquante,
même hors fenêtre d'attaque, est exclu par prudence : on ne peut pas
garantir qu'une activité non journalisée n'a pas eu lieu.
"""

# Adresses de la VM surveillée, sur toute la période de capture.
TARGET_IPS = ("192.168.1.249", "192.168.1.112")

# IP ayant conduit au moins une attaque : jamais étiquetées bénignes.
ATTACKER_IPS = ("192.168.1.225", "192.168.1.230", "192.168.1.159")

# Une fenêtre = (borne basse incluse, borne haute EXCLUE, src, dst,
# port de destination ou None pour « tous », classe).
# Les bornes sont des préfixes de timestamp ISO comparés
# lexicographiquement, comme dans flow_feature_extractor.iter_flow_events.
ATTACK_WINDOWS = [
    ("2026-09-13T13:21", "2026-09-13T13:23", "192.168.1.225", "192.168.1.249", None, "Reconnaissance"),
    # --- Scan de ports nmap -> Reconnaissance -------------------------
    # 28/07 : deux rafales vers l'ancienne adresse .112, 97-98 ports
    # distincts par minute.
    ("2026-07-28T21:25", "2026-07-28T21:27", "192.168.1.225", "192.168.1.112", None, "Reconnaissance"),
    ("2026-07-28T22:03", "2026-07-28T22:06", "192.168.1.225", "192.168.1.112", None, "Reconnaissance"),
    # 31/08 : campagne principale, 1004 ports de destination distincts.
    ("2026-09-13T13:21", "2026-09-13T13:23", "192.168.1.225", "192.168.1.249", None, "Reconnaissance"),
    ("2026-08-31T23:47", "2026-08-31T23:49", "192.168.1.225", "192.168.1.249", None, "Reconnaissance"),

    # --- Flood TCP sur le port 22 -> DoS ------------------------------
    # Quatre rafales de 300 flux TCP complets (drapeaux 1f) en une minute.
    ("2026-08-15T00:18", "2026-08-15T00:19", "192.168.1.225", "192.168.1.249", 22, "DoS"),
    ("2026-08-15T12:48", "2026-08-15T12:49", "192.168.1.230", "192.168.1.249", 22, "DoS"),
    ("2026-08-15T12:52", "2026-08-15T12:53", "192.168.1.230", "192.168.1.249", 22, "DoS"),
    ("2026-08-31T23:45", "2026-08-31T23:46", "192.168.1.225", "192.168.1.249", 22, "DoS"),

    # --- Force brute SSH -> BruteForce --------------------------------
    ("2026-09-13T13:35", "2026-09-13T13:50", "192.168.1.225", "192.168.1.249", 22, "BruteForce"),
    ("2026-09-13T13:35", "2026-09-13T13:38", "192.168.1.225", "192.168.1.249", 22, "BruteForce"),
    # Bornes élargies d'une minute autour des échecs auth.log, pour
    # capturer le flux Suricata qui porte la tentative (un flux est
    # journalisé à sa fermeture ou à son timeout, donc après l'échec).
    ("2026-08-04T21:57", "2026-08-04T22:00", "192.168.1.159", "192.168.1.249", 22, "BruteForce"),
    ("2026-08-04T22:05", "2026-08-04T22:36", "192.168.1.159", "192.168.1.249", 22, "BruteForce"),
    ("2026-08-06T20:39", "2026-08-06T21:00", "192.168.1.159", "192.168.1.249", 22, "BruteForce"),
    ("2026-08-06T21:00", "2026-08-06T21:24", "192.168.1.159", "192.168.1.249", 22, "BruteForce"),
]

# Périodes retenues comme trafic normal. Aucune attaque journalisée, et
# tout flux impliquant une IP de ATTACKER_IPS y est écarté.
BENIGN_WINDOWS = [
    ("2026-08-20T22", "2026-08-21T03"),
    ("2026-08-17T22", "2026-08-18T02"),
    ("2026-08-10T20", "2026-08-11T00"),
    ("2026-08-07T22", "2026-08-08T00"),
]


def _attack_campaign_id(lo: str, w_src: str, label: str) -> str:
    """
    Identifiant de CAMPAGNE d'un flux d'attaque, à la granularité
    (classe, attaquant, jour). Les fenêtres d'une même session découpée en
    plusieurs bornes -- ex. les deux fenêtres de force brute du 04/08 --
    portent ainsi le même identifiant. C'est cette granularité qui sert de
    groupe pour la validation croisée sans fuite (train_local_flow_model.py) :
    des flux d'une même campagne sont fortement corrélés et ne doivent
    jamais se retrouver des deux côtés d'un pli.
    """
    return f"{label}:{w_src}:{lo[:10]}"


def label_and_campaign(event: dict):
    """
    Comme label_flow, mais retourne (classe, campaign_id). Retourne
    (None, None) si le flux n'est couvert par aucune fenêtre. Pour un flux
    bénin, campaign_id = "Benign:<date de la fenêtre bénigne>".
    """
    ts = event.get("timestamp", "")
    src = event.get("src_ip")
    dst = event.get("dest_ip")
    dport = event.get("dest_port")

    for lo, hi, w_src, w_dst, w_port, label in ATTACK_WINDOWS:
        if not (lo <= ts < hi):
            continue
        if src != w_src or dst != w_dst:
            continue
        if w_port is not None and dport != w_port:
            continue
        return label, _attack_campaign_id(lo, w_src, label)

    for lo, hi in BENIGN_WINDOWS:
        if lo <= ts < hi:
            if src in ATTACKER_IPS or dst in ATTACKER_IPS:
                return None, None
            return "Benign", f"Benign:{lo[:10]}"

    return None, None


def label_flow(event: dict) -> str:
    """
    Retourne la classe de vérité terrain d'un enregistrement `flow`
    Suricata : nom d'attaque, "Benign", ou None si le flux n'est couvert
    par aucune fenêtre (il est alors EXCLU du test, jamais supposé
    bénin).
    """
    ts = event.get("timestamp", "")
    src = event.get("src_ip")
    dst = event.get("dest_ip")
    dport = event.get("dest_port")

    for lo, hi, w_src, w_dst, w_port, label in ATTACK_WINDOWS:
        if not (lo <= ts < hi):
            continue
        if src != w_src or dst != w_dst:
            continue
        if w_port is not None and dport != w_port:
            continue
        return label

    for lo, hi in BENIGN_WINDOWS:
        if lo <= ts < hi:
            if src in ATTACKER_IPS or dst in ATTACKER_IPS:
                return None
            return "Benign"

    return None


if __name__ == "__main__":
    print(f"{len(ATTACK_WINDOWS)} fenêtres d'attaque, {len(BENIGN_WINDOWS)} fenêtres bénignes.")
    from collections import Counter
    print("Classes d'attaque déclarées :", Counter(w[5] for w in ATTACK_WINDOWS))


# --------------------------------------------------------------------------
# Correspondance classes fines -> catégories parentes du jeu source
# --------------------------------------------------------------------------
# La colonne `Attack` de NF-CSE-CIC-IDS2018 contient 15 classes FINES
# (« DoS attacks-Hulk », « SSH-Bruteforce »...), alors que la page de
# publication du jeu décrit 7 catégories PARENTES. Les deux niveaux
# coexistent et il faut les distinguer explicitement, sans quoi une
# comparaison avec la vérité terrain locale (exprimée en catégories)
# renvoie zéro par simple non-correspondance de chaînes, ce qui se lirait
# à tort comme un échec de transfert.
#
# Correspondance NON devinée : chaque somme ci-dessous a été confrontée
# aux effectifs publiés par les auteurs, et les six tombent exactement.
#   BruteForce   193 360 + 94 237                     = 287 597
#   DoS          108 136 + 105 550 + 32 850 + 22 825  = 269 361
#   DDoS         378 199 +   1 667 +    230           = 380 096
#   Web Attacks    2 613 +   1 745 +     36           =   4 394
#   Bot / Infiltration : classes uniques, inchangées  =  15 683 / 62 072
DATASET_PARENT_CATEGORY = {
    "Benign": "Benign",
    "FTP-BruteForce": "BruteForce",
    "SSH-Bruteforce": "BruteForce",
    "DoS attacks-Hulk": "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",
    "DoS attacks-GoldenEye": "DoS",
    "DoS attacks-Slowloris": "DoS",
    "DDoS attacks-LOIC-HTTP": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",
    "DDOS attack-HOIC": "DDoS",
    "Brute Force -Web": "Web Attacks",
    "Brute Force -XSS": "Web Attacks",
    "SQL Injection": "Web Attacks",
    "Bot": "Bot",
    "Infilteration": "Infiltration",
}

# Effectifs publiés par les auteurs, conservés pour que
# verify_parent_mapping() puisse revérifier la correspondance.
PUBLISHED_PARENT_COUNTS = {
    "Benign": 7373198, "BruteForce": 287597, "Bot": 15683,
    "DoS": 269361, "DDoS": 380096, "Infiltration": 62072,
    "Web Attacks": 4394,
}


def to_parent_category(fine_label: str) -> str:
    """
    Traduit une classe fine du jeu source en catégorie parente. Lève
    KeyError sur une classe inconnue plutôt que de retourner un défaut :
    une classe non répertoriée signifie que le jeu a changé, et un repli
    silencieux fausserait toute évaluation en aval.
    """
    return DATASET_PARENT_CATEGORY[fine_label]


def verify_parent_mapping(csv_path: str) -> bool:
    """
    Utilitaire de maintenance : recompte les classes fines du CSV, les
    agrège par catégorie parente et confronte le résultat aux effectifs
    publiés par les auteurs du jeu.
    """
    import pandas as pd
    from collections import Counter

    counts = Counter()
    for chunk in pd.read_csv(csv_path, usecols=["Attack"], chunksize=2_000_000):
        counts.update(chunk["Attack"].value_counts().to_dict())

    unknown = sorted(set(counts) - set(DATASET_PARENT_CATEGORY))
    if unknown:
        print(f"Classes fines inconnues de la table : {unknown}")
        return False

    parents = Counter()
    for fine, n in counts.items():
        parents[DATASET_PARENT_CATEGORY[fine]] += n

    print(f"{'catégorie':<14} {'recompté':>10} {'publié':>10}  verdict")
    all_ok = True
    for parent in sorted(PUBLISHED_PARENT_COUNTS):
        got, expected = parents.get(parent, 0), PUBLISHED_PARENT_COUNTS[parent]
        ok = got == expected
        all_ok = all_ok and ok
        print(f"{parent:<14} {got:>10} {expected:>10}  {'OK' if ok else 'ÉCART'}")
    print("\nOK : la correspondance parente reproduit exactement les effectifs publiés."
          if all_ok else "\nÉCART — ne pas utiliser DATASET_PARENT_CATEGORY en l'état.")
    return all_ok
