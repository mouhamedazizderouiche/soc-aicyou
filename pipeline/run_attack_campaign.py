"""
run_attack_campaign.py

Orchestration des campagnes d'attaque servant à étoffer le jeu de flux
locaux étiquetés (netflow_ground_truth.ATTACK_WINDOWS). Trois sous-commandes :

  plan    : imprime les commandes EXACTES à lancer côté attaquant. L'attaquant
            est une machine externe (VM Windows / poste Kali) : ce script ne
            peut PAS la déclencher lui-même. Il documente, il ne lance pas.

  record  : après une campagne, scanne eve.json sur l'intervalle donné,
            détecte automatiquement les minutes où l'attaquant a effectivement
            touché la cible, et imprime le(s) tuple(s) ATTACK_WINDOWS prêt(s)
            à coller dans netflow_ground_truth.py. Remplace l'écriture
            manuelle des fenêtres, source d'erreurs de fuseau et de bornes.

  verify  : passe l'intervalle par flow_feature_extractor et rapporte combien
            de flux ont RÉELLEMENT été capturés, par (drapeaux TCP, état),
            pour confirmer que l'attaque a laissé une trace exploitable avant
            de l'ajouter au jeu.

CONTRAINTE DE CAPTURE, VÉRIFIÉE, À CONNAÎTRE AVANT DE PLANIFIER
--------------------------------------------------------------
Suricata capture l'interface physique (ens33, mode host). Un flux n'est
capturé QUE s'il traverse ce fil. Conséquences mesurées le 07/09/2026 :
  - une attaque de la machine surveillée CONTRE ELLE-MÊME (192.168.1.249
    -> 192.168.1.249) passe par la loopback et N'EST PAS capturée (test :
    0 flux) ;
  - il faut donc un attaquant DISTINCT de la cible sur le même segment.
C'est pourquoi la force brute doit venir de la VM externe : c'est le seul
moyen d'obtenir des flux entrants capturés vers le port 22 de la cible.
"""

import argparse
import collections
import json
from datetime import datetime, timedelta, timezone

MONITORED_HOST = "192.168.1.249"
EVE_PATH = "/var/log/suricata/eve.json"

# Recettes documentées par classe. Chaque recette dit quoi lancer côté
# ATTAQUANT (machine externe) pour produire des flux de la classe voulue.
RECIPES = {
    "BruteForce": {
        "tactic": "InitialAccess_CredentialAccess",
        "why": "SSH brute-force -> nombreux flux courts vers le port 22 de la cible",
        "target_port": 22,
        "windows_powershell": (
            "# Depuis la VM Windows attaquante (Posh-SSH), contre la cible {target}:\n"
            "$ErrorActionPreference='SilentlyContinue'\n"
            "$pw = 1..400 | % {{ \"wrong_$_\" }}\n"
            "foreach ($p in $pw) {{\n"
            "  New-SSHSession -ComputerName {target} -Credential "
            "(New-Object PSCredential('bftest',(ConvertTo-SecureString $p -AsPlainText -Force))) "
            "-AcceptKey -ConnectionTimeout 3 | Out-Null\n"
            "}}"
        ),
        "kali_alt": "hydra -l bftest -P /usr/share/wordlists/rockyou.txt -t 4 ssh://{target}",
        "note": (
            "Viser >= 300 tentatives pour dépasser nettement les 56 flux "
            "existants. Chaque tentative = 1 flux TCP complet vers :22."
        ),
    },
    "Reconnaissance": {
        "tactic": "Reconnaissance",
        "why": "scan de ports -> nombreux flux SYN courts vers des ports variés",
        "target_port": None,
        "windows_powershell": "# Depuis la VM Windows : nmap -sS -p1-1000 {target}",
        "kali_alt": "nmap -sS -p1-1000 -T4 {target}",
        "note": "Le nombre de ports distincts touchés est la signature de l'outil.",
    },
    "DoS": {
        "tactic": "Impact",
        "why": "flood TCP mono-port -> rafale dense de flux vers un port unique",
        "target_port": 22,
        "windows_powershell": (
            "# Depuis la VM Windows, flood de connexions TCP sur :22 :\n"
            "1..300 | % {{ (New-Object Net.Sockets.TcpClient).Connect('{target}',22) }}"
        ),
        "kali_alt": "hping3 -S -p 22 --flood {target}   # ou: nping --tcp -p22 -c 300 {target}",
        "note": "300 connexions en < 1 min = signature de flood, cohérente avec l'existant.",
    },
}


def cmd_plan(args):
    recipe = RECIPES[args.klass]
    target = args.target
    print("=" * 72)
    print(f"CAMPAGNE '{args.klass}' -> tactique MITRE {recipe['tactic']}")
    print("=" * 72)
    print(f"Cible (machine surveillée) : {target}")
    print(f"Pourquoi : {recipe['why']}")
    print(f"\n>>> À LANCER SUR LA MACHINE ATTAQUANTE (externe, ce script ne la pilote pas) :\n")
    print("--- PowerShell (VM Windows) ---")
    print(recipe["windows_powershell"].format(target=target))
    print("\n--- ou équivalent Kali/Linux ---")
    print(recipe["kali_alt"].format(target=target))
    print(f"\nNote : {recipe['note']}")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
    print("\n>>> APRÈS la campagne, enregistrer la fenêtre automatiquement :")
    print(f"    python run_attack_campaign.py record --klass {args.klass} "
          f"--attacker <IP_ATTAQUANT> --since {now} --until <maintenant+marge>")


def _iter_flows(since, until):
    with open(EVE_PATH, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if '"event_type"' not in line or '"flow"' not in line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("event_type") != "flow":
                continue
            ts = e.get("timestamp", "")
            if since and ts < since:
                continue
            if until and ts > until:
                continue
            yield e


def cmd_record(args):
    recipe = RECIPES[args.klass]
    port = recipe["target_port"]
    target = args.target
    attacker = args.attacker

    minutes = collections.Counter()
    flags = collections.Counter()
    for e in _iter_flows(args.since, args.until):
        if e.get("src_ip") != attacker or e.get("dest_ip") != target:
            continue
        if port is not None and e.get("dest_port") != port:
            continue
        minutes[e["timestamp"][:16]] += 1
        fl = (e.get("tcp", {}) or {}).get("tcp_flags")
        flags[fl] += 1

    if not minutes:
        print(f"AUCUN flux {attacker} -> {target}"
              f"{f':{port}' if port else ''} sur [{args.since}, {args.until}].")
        print("L'attaque n'a pas été capturée. Vérifier : attaquant distinct de la")
        print("cible (sinon loopback, non capturé), et bornes temporelles (UTC).")
        return

    lo = min(minutes)
    # borne haute exclue = minute suivant la dernière minute active
    hi_dt = datetime.strptime(max(minutes), "%Y-%m-%dT%H:%M") + timedelta(minutes=1)
    hi = hi_dt.strftime("%Y-%m-%dT%H:%M")
    total = sum(minutes.values())

    print(f"Flux {attacker} -> {target}"
          f"{f':{port}' if port else ''} capturés : {total} "
          f"sur {len(minutes)} minute(s) active(s).")
    print(f"Drapeaux TCP observés : {dict(flags.most_common(5))}")
    print("\n>>> Tuple à coller dans netflow_ground_truth.ATTACK_WINDOWS :\n")
    port_field = str(port) if port is not None else "None"
    print(f'    ("{lo}", "{hi}", "{attacker}", "{target}", {port_field}, "{args.klass}"),')
    print("\nPuis reconstruire le jeu : python build_live_flow_dataset.py")


def cmd_verify(args):
    from flow_feature_extractor import extract_flow_features
    from netflow_ground_truth import label_and_campaign

    events = list(_iter_flows(args.since, args.until))
    df, stats = extract_flow_features(events)
    print(stats.summary())

    by_class = collections.Counter()
    by_campaign = collections.defaultdict(set)
    for e in events:
        lab, camp = label_and_campaign(e)
        if lab is not None:
            by_class[lab] += 1
            by_campaign[lab].add(camp)
    print("\nFlux capturés retenus par classe de vérité terrain (sur l'intervalle) :")
    if not by_class:
        print("  aucun flux ne tombe dans une fenêtre étiquetée -- penser à")
        print("  ajouter d'abord le tuple via 'record'.")
    for lab in sorted(by_class):
        print(f"  {lab:<16} {by_class[lab]:6d} flux  ({len(by_campaign[lab])} campagne(s))")


def main():
    ap = argparse.ArgumentParser(description="Orchestration des campagnes d'attaque locales.")
    sub = ap.add_subparsers(dest="mode", required=True)

    p_plan = sub.add_parser("plan", help="imprime les commandes à lancer côté attaquant")
    p_plan.add_argument("--klass", required=True, choices=list(RECIPES))
    p_plan.add_argument("--target", default=MONITORED_HOST)
    p_plan.set_defaults(func=cmd_plan)

    p_rec = sub.add_parser("record", help="détecte la fenêtre capturée et imprime le tuple")
    p_rec.add_argument("--klass", required=True, choices=list(RECIPES))
    p_rec.add_argument("--attacker", required=True, help="IP de la machine attaquante")
    p_rec.add_argument("--target", default=MONITORED_HOST)
    p_rec.add_argument("--since", required=True, help='borne basse UTC, ex. "2026-09-07T14:00"')
    p_rec.add_argument("--until", required=True, help='borne haute UTC')
    p_rec.set_defaults(func=cmd_record)

    p_ver = sub.add_parser("verify", help="compte les flux capturés/retenus sur l'intervalle")
    p_ver.add_argument("--since", required=True)
    p_ver.add_argument("--until", required=True)
    p_ver.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
