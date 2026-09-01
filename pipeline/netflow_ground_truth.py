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
    # --- Scan de ports nmap -> Reconnaissance -------------------------
    # 28/07 : deux rafales vers l'ancienne adresse .112, 97-98 ports
    # distincts par minute.
    ("2026-07-28T21:25", "2026-07-28T21:27", "192.168.1.225", "192.168.1.112", None, "Reconnaissance"),
    ("2026-07-28T22:03", "2026-07-28T22:06", "192.168.1.225", "192.168.1.112", None, "Reconnaissance"),
    # 31/08 : campagne principale, 1004 ports de destination distincts.
    ("2026-08-31T23:47", "2026-08-31T23:49", "192.168.1.225", "192.168.1.249", None, "Reconnaissance"),

    # --- Flood TCP sur le port 22 -> DoS ------------------------------
    # Quatre rafales de 300 flux TCP complets (drapeaux 1f) en une minute.
    ("2026-08-15T00:18", "2026-08-15T00:19", "192.168.1.225", "192.168.1.249", 22, "DoS"),
    ("2026-08-15T12:48", "2026-08-15T12:49", "192.168.1.230", "192.168.1.249", 22, "DoS"),
    ("2026-08-15T12:52", "2026-08-15T12:53", "192.168.1.230", "192.168.1.249", 22, "DoS"),
    ("2026-08-31T23:45", "2026-08-31T23:46", "192.168.1.225", "192.168.1.249", 22, "DoS"),

    # --- Force brute SSH -> BruteForce --------------------------------
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
