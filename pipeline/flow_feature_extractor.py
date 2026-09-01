"""
flow_feature_extractor.py

Extrait les 12 features du schéma NetFlow standard v1 (Sarhan et al.,
"NetFlow Datasets for Machine Learning-Based Network Intrusion Detection
Systems", BDTA 2020 / arXiv:2101.11315) depuis les enregistrements
`event_type: flow` de Suricata (eve.json).

RAISON D'ÊTRE
-------------
Le pipeline live existant (feature_extractor.py) produit 14 agrégats par
fenêtre temporelle ; les modèles du projet sont entraînés sur NSL-KDD
(41 colonnes de détail par session). Les deux espaces de features n'ont
aucun recouvrement -- feature_schema.py rend cet échec explicite mais ne
le résout pas. Ce module ouvre la seconde voie : produire, depuis le
trafic réel, un schéma **identique** à celui d'un jeu de données public
étiqueté (NF-CSE-CIC-IDS2018), afin qu'un modèle entraîné sur ce jeu
puisse être appliqué au trafic live sans couche d'adaptation.

Il ne remplace pas feature_extractor.py : les deux coexistent (voir
docs/architecture.md, section 7).

CONTRAT
-------
Entrée  : dicts JSON issus de eve.json avec event_type == "flow".
Sortie  : DataFrame dont les colonnes sont EXACTEMENT NETFLOW_V1_COLUMNS,
          dans cet ordre, avec les dtypes déclarés dans NETFLOW_V1_DTYPES.
Tout enregistrement qui ne peut pas être représenté fidèlement dans ce
schéma est REJETÉ et comptabilisé par motif (ExtractionStats) plutôt que
rempli avec une valeur inventée. La validation
(validate_netflow_v1_schema) est appelée avant toute écriture et doit
l'être avant tout appel à predict()/predict_proba().

PÉRIMÈTRE ET LIMITES CONNUES
----------------------------
1. IPv4 uniquement. Le schéma NetFlow v1 déclare IPV4_SRC_ADDR /
   IPV4_DST_ADDR et NF-CSE-CIC-IDS2018 ne contient que de l'IPv4. Les
   flux IPv6 (mesuré : ~21% des flux sur ce réseau, essentiellement
   mDNS/ICMPv6 de découverte) sont rejetés, pas convertis.
2. Flux sans ports (ICMP, IPv6-ICMP) : L4_SRC_PORT / L4_DST_PORT sont
   mis à 0, convention utilisée par nProbe et présente dans le jeu de
   données. C'est le seul défaut volontairement comblé, parce que 0
   n'est pas un port légal et ne peut donc pas être confondu avec une
   valeur réelle.
3. TCP_FLAGS : absent des flux non-TCP -> 0 (aucun drapeau TCP observé).
   Pour les flux TCP, Suricata expose `tcp.tcp_flags` en hexadécimal
   (ex. "1b") : c'est l'OU logique des drapeaux vus dans les deux sens,
   ce qui correspond à la sémantique TCP_FLAGS de nProbe.
4. FLOW_DURATION_MILLISECONDS est bornée par les timeouts de flux de
   Suricata (suricata.yaml : 600 s pour un flux TCP established). Un
   flux réellement plus long est découpé en plusieurs enregistrements ;
   la durée extraite est donc une borne inférieure. NF-CSE-CIC-IDS2018
   est généré par nProbe avec ses propres timeouts -- cet écart de
   segmentation est une source de décalage de domaine documentée, pas
   corrigeable côté extraction.
5. L7_PROTO : voir L7_PROTO_BY_APP_PROTO ci-dessous. Le jeu de données
   encode ce champ avec les identifiants numériques nDPI (utilisés par
   nProbe) ; Suricata expose un nom (`app_proto`). La correspondance est
   dérivée empiriquement du jeu de données lui-même, pas devinée --
   lancer `python flow_feature_extractor.py --verify-l7` pour la
   revérifier.
"""

from dataclasses import dataclass, field
from datetime import datetime
import argparse
import ipaddress
import json
import logging
import os

import pandas as pd

logger = logging.getLogger("flow_feature_extractor")


class FlowFeatureError(Exception):
    """
    Levée quand un DataFrame ne correspond pas au schéma NetFlow v1
    attendu, ou quand la configuration du module est incohérente
    (mapping L7 manquant, etc.). Message toujours actionnable.
    """
    pass


# --------------------------------------------------------------------------
# Schéma
# --------------------------------------------------------------------------
# Ordre et noms repris tels quels du jeu NF-CSE-CIC-IDS2018 v1 (en-tête du
# CSV, hors colonnes d'étiquetage Label/Attack). Vérifiable avec
# `python flow_feature_extractor.py --verify-schema <chemin_csv>`.
NETFLOW_V1_COLUMNS = [
    "IPV4_SRC_ADDR",
    "L4_SRC_PORT",
    "IPV4_DST_ADDR",
    "L4_DST_PORT",
    "PROTOCOL",
    "L7_PROTO",
    "IN_BYTES",
    "OUT_BYTES",
    "IN_PKTS",
    "OUT_PKTS",
    "TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS",
]

# Colonnes réellement exploitables par un modèle. Les adresses IP sont
# conservées dans la sortie (traçabilité analyste : savoir QUI est
# concerné) mais DOIVENT être exclues de l'entrée du modèle : elles sont
# spécifiques au plan d'adressage du jeu d'entraînement et
# n'ont aucun pouvoir de généralisation vers un autre réseau -- les
# inclure produirait un modèle qui mémorise les IP du testbed CIC.
NETFLOW_V1_MODEL_COLUMNS = [
    c for c in NETFLOW_V1_COLUMNS if c not in ("IPV4_SRC_ADDR", "IPV4_DST_ADDR")
]

NETFLOW_V1_DTYPES = {
    "IPV4_SRC_ADDR": "object",
    "IPV4_DST_ADDR": "object",
    "L4_SRC_PORT": "int64",
    "L4_DST_PORT": "int64",
    "PROTOCOL": "int64",
    "L7_PROTO": "float64",
    "IN_BYTES": "int64",
    "OUT_BYTES": "int64",
    "IN_PKTS": "int64",
    "OUT_PKTS": "int64",
    "TCP_FLAGS": "int64",
    "FLOW_DURATION_MILLISECONDS": "int64",
}

# Numéros de protocole IANA. Suricata écrit un nom ; NetFlow attend le
# numéro. Table volontairement restreinte aux protocoles réellement
# observés ou plausibles sur ce réseau : un protocole inconnu est rejeté
# et compté, jamais mappé sur une valeur par défaut.
PROTOCOL_NUMBERS = {
    "ICMP": 1,
    "IGMP": 2,
    "TCP": 6,
    "UDP": 17,
    "GRE": 47,
    "ESP": 50,
    "AH": 51,
    "IPv6-ICMP": 58,
    "SCTP": 132,
}

# Correspondance nom Suricata `app_proto` -> identifiant numérique nDPI
# utilisé comme L7_PROTO dans les jeux NF-*. DÉRIVÉE EMPIRIQUEMENT du
# jeu NF-CSE-CIC-IDS2018 v1 (valeur L7_PROTO majoritaire pour chaque port
# applicatif de référence), pas reprise d'une documentation : voir
# verify_l7_proto_map(). Les entrées non confirmées empiriquement ne
# figurent pas dans cette table -- un app_proto absent tombe sur
# L7_PROTO_UNKNOWN, qui est la valeur que nDPI lui-même utilise pour
# "protocole non identifié", donc un défaut sémantiquement correct et
# non un remplissage arbitraire.
L7_PROTO_UNKNOWN = 0.0

# Chaque entrée a été confirmée par double vérification sur les 8 392 401
# lignes du jeu : (a) valeur L7_PROTO majoritaire pour le port applicatif
# de référence, (b) port de destination majoritaire pour cette valeur
# L7_PROTO. Seules les correspondances dont la vérification inverse donne
# >= 96% sur un port unique figurent ici. Relancer avec --verify-l7.
L7_PROTO_BY_APP_PROTO = {
    "smtp": 3.0,      # port 25   (vérif. inverse : 100%)
    "dns": 5.0,       # port 53   (100%)
    "http": 7.0,      # port 80   (100%)
    "ntp": 9.0,       # port 123  (100%)
    "nbss": 10.0,     # port 139  (98%)
    "smb": 41.0,      # port 445  (100%)
    "telnet": 77.0,   # port 23   (100%)
    "ikev2": 79.0,    # port 500  (100%)
    "rdp": 88.0,      # port 3389 (99%)
    "tls": 91.0,      # port 443  (100%)
    "ssh": 92.0,      # port 22   (99%)
    "ldap": 112.0,    # port 389  (100%)
    "mssql": 114.0,   # port 1433 (96%)
}

# Volontairement ABSENTS de la table, et pourquoi -- ne pas les ajouter
# sans nouvelle vérification :
#   ftp, dhcp, snmp : nDPI ne les identifie pas dans ce jeu (ports 21,
#     67/68, 161 -> L7_PROTO = 0 à 99,7-100%). Les faire tomber sur 0 via
#     L7_PROTO_UNKNOWN reproduit donc EXACTEMENT le comportement du jeu
#     d'entraînement ; les mapper vers une valeur nDPI théorique
#     introduirait au contraire un écart.
#   quic : quasi absent du jeu (capturé en 2018), aucune valeur stable à
#     dériver. Tombe sur 0.
#   failed : valeur Suricata signifiant « identification échouée », dont 0
#     est la traduction exacte côté nDPI.

# Ports applicatifs de référence servant à la dérivation ET à sa
# revérification. Clé = port, valeur = nom app_proto Suricata attendu.
L7_REFERENCE_PORTS = {
    25: "smtp", 53: "dns", 80: "http", 123: "ntp", 139: "nbss",
    445: "smb", 23: "telnet", 500: "ikev2", 3389: "rdp", 443: "tls",
    22: "ssh", 389: "ldap", 1433: "mssql",
}


@dataclass
class ExtractionStats:
    """
    Compte les enregistrements traités et les motifs de rejet. Exposé
    dans la sortie plutôt que masqué : un taux de rejet inattendu est le
    premier symptôme d'un changement de format en amont.
    """
    seen: int = 0
    accepted: int = 0
    rejected: dict = field(default_factory=dict)

    def reject(self, reason: str) -> None:
        self.rejected[reason] = self.rejected.get(reason, 0) + 1

    def summary(self) -> str:
        lines = [
            f"Flux lus       : {self.seen}",
            f"Flux retenus   : {self.accepted}"
            + (f" ({self.accepted / self.seen:.1%})" if self.seen else ""),
        ]
        if self.rejected:
            lines.append("Flux rejetés par motif :")
            for reason, count in sorted(self.rejected.items(), key=lambda kv: -kv[1]):
                lines.append(f"  - {reason} : {count}")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------

def _parse_suricata_timestamp(value: str) -> datetime:
    """
    Parse un timestamp Suricata ISO 8601 avec offset compact (+0000).
    datetime.fromisoformat gère ce format à partir de Python 3.11 ; la
    normalisation explicite garde le module compatible en amont et rend
    l'échec lisible si le format change.
    """
    return datetime.fromisoformat(value)


def _is_ipv4(address: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(address), ipaddress.IPv4Address)
    except ValueError:
        return False


def flow_record_to_features(event: dict, stats: ExtractionStats = None) -> dict:
    """
    Convertit UN enregistrement `event_type: flow` de Suricata en une
    ligne au schéma NetFlow v1. Retourne None si l'enregistrement ne peut
    pas être représenté fidèlement (le motif est alors comptabilisé dans
    `stats`), plutôt que d'inventer des valeurs.
    """
    stats = stats if stats is not None else ExtractionStats()

    if event.get("event_type") != "flow":
        stats.reject("event_type != flow")
        return None

    src_ip = event.get("src_ip")
    dst_ip = event.get("dest_ip")
    if not src_ip or not dst_ip:
        stats.reject("adresse source ou destination absente")
        return None
    if not _is_ipv4(src_ip) or not _is_ipv4(dst_ip):
        stats.reject("flux non-IPv4 (hors périmètre du schéma NetFlow v1)")
        return None

    proto_name = event.get("proto")
    if proto_name not in PROTOCOL_NUMBERS:
        stats.reject(f"protocole non répertorié : {proto_name!r}")
        return None
    protocol = PROTOCOL_NUMBERS[proto_name]

    flow = event.get("flow")
    if not isinstance(flow, dict):
        stats.reject("bloc 'flow' absent ou malformé")
        return None

    for key in ("bytes_toserver", "bytes_toclient", "pkts_toserver", "pkts_toclient"):
        if not isinstance(flow.get(key), int):
            stats.reject(f"compteur flow.{key} absent ou non entier")
            return None

    start_raw, end_raw = flow.get("start"), flow.get("end")
    if not start_raw or not end_raw:
        stats.reject("flow.start ou flow.end absent")
        return None
    try:
        duration_ms = int(
            (_parse_suricata_timestamp(end_raw) - _parse_suricata_timestamp(start_raw))
            .total_seconds() * 1000
        )
    except ValueError:
        stats.reject("flow.start / flow.end non parsables")
        return None
    if duration_ms < 0:
        stats.reject("durée de flux négative (end < start)")
        return None

    # Ports : absents sur ICMP/IPv6-ICMP par construction. 0 est la
    # convention nProbe et n'est pas un port légal -- pas d'ambiguïté.
    src_port = event.get("src_port")
    dst_port = event.get("dest_port")
    src_port = 0 if src_port is None else int(src_port)
    dst_port = 0 if dst_port is None else int(dst_port)

    # TCP_FLAGS : hexadécimal côté Suricata, entier côté NetFlow.
    # Absent hors TCP -> 0, qui signifie "aucun drapeau TCP", vrai.
    tcp_block = event.get("tcp")
    if isinstance(tcp_block, dict) and tcp_block.get("tcp_flags") is not None:
        try:
            tcp_flags = int(str(tcp_block["tcp_flags"]), 16)
        except ValueError:
            stats.reject(f"tcp.tcp_flags non hexadécimal : {tcp_block['tcp_flags']!r}")
            return None
    else:
        tcp_flags = 0

    app_proto = event.get("app_proto")
    l7_proto = L7_PROTO_BY_APP_PROTO.get(app_proto, L7_PROTO_UNKNOWN)

    stats.accepted += 1
    return {
        "IPV4_SRC_ADDR": src_ip,
        "L4_SRC_PORT": src_port,
        "IPV4_DST_ADDR": dst_ip,
        "L4_DST_PORT": dst_port,
        "PROTOCOL": protocol,
        "L7_PROTO": float(l7_proto),
        "IN_BYTES": int(flow["bytes_toserver"]),
        "OUT_BYTES": int(flow["bytes_toclient"]),
        "IN_PKTS": int(flow["pkts_toserver"]),
        "OUT_PKTS": int(flow["pkts_toclient"]),
        "TCP_FLAGS": tcp_flags,
        "FLOW_DURATION_MILLISECONDS": duration_ms,
    }


def iter_flow_events(eve_path: str, since: str = None, until: str = None):
    """
    Parcourt eve.json en flux (le fichier fait plusieurs centaines de Mo
    en usage réel : jamais de chargement intégral en mémoire) et rend les
    enregistrements `event_type: flow`.

    since / until : préfixes de timestamp ISO comparés lexicographiquement
    (ex. "2026-08-31T23:47"). La comparaison lexicographique est valide
    ici parce que tous les timestamps Suricata partagent le même format
    et le même offset UTC dans un fichier donné.
    """
    with open(eve_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            # Pré-filtre textuel : évite de parser en JSON les ~85% de
            # lignes qui ne sont pas des flux (gain mesuré ~4x).
            if '"event_type"' not in line or '"flow"' not in line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "flow":
                continue
            ts = event.get("timestamp", "")
            if since and ts < since:
                continue
            if until and ts > until:
                continue
            yield event


def extract_flow_features(events, stats: ExtractionStats = None) -> tuple:
    """
    Transforme un itérable d'enregistrements `flow` en DataFrame au
    schéma NetFlow v1. Retourne (DataFrame, ExtractionStats).

    Le DataFrame est validé contre le contrat avant d'être retourné :
    aucun appelant ne peut recevoir une sortie hors schéma.
    """
    stats = stats if stats is not None else ExtractionStats()
    rows = []
    for event in events:
        stats.seen += 1
        row = flow_record_to_features(event, stats)
        if row is not None:
            rows.append(row)

    df = pd.DataFrame(rows, columns=NETFLOW_V1_COLUMNS)
    for column, dtype in NETFLOW_V1_DTYPES.items():
        if dtype != "object":
            df[column] = df[column].astype(dtype)

    validate_netflow_v1_schema(df, context="extract_flow_features")
    return df, stats


# --------------------------------------------------------------------------
# Contrat de schéma
# --------------------------------------------------------------------------

def validate_netflow_v1_schema(X: pd.DataFrame, context: str = "",
                                model_input: bool = False) -> None:
    """
    Valide qu'un DataFrame correspond au schéma NetFlow v1. À appeler
    avant toute écriture et avant tout predict()/predict_proba().

    model_input=True valide contre NETFLOW_V1_MODEL_COLUMNS (sans les
    adresses IP, qui ne doivent jamais entrer dans le modèle).

    Même principe que feature_schema.validate_nsl_kdd_schema : on
    transforme un échec silencieux ou cryptique en échec diagnostiqué.
    """
    expected = NETFLOW_V1_MODEL_COLUMNS if model_input else NETFLOW_V1_COLUMNS
    actual = list(X.columns)

    missing = [c for c in expected if c not in actual]
    unexpected = [c for c in actual if c not in expected]

    problems = []
    if missing:
        problems.append(f"Colonnes attendues absentes ({len(missing)}) : {missing}")
    if unexpected:
        problems.append(f"Colonnes présentes non attendues ({len(unexpected)}) : {unexpected}")
    if not missing and not unexpected and actual != expected:
        problems.append(
            f"Colonnes correctes mais ordre différent.\n  attendu : {expected}\n  obtenu  : {actual}"
        )

    if not problems and len(X) > 0:
        for column in expected:
            expected_dtype = NETFLOW_V1_DTYPES[column]
            if expected_dtype == "object":
                continue
            if not pd.api.types.is_numeric_dtype(X[column]):
                problems.append(
                    f"Colonne {column} : dtype numérique attendu ({expected_dtype}), "
                    f"obtenu {X[column].dtype}"
                )

    if problems:
        header = (
            f"Schéma NetFlow v1 invalide{f' ({context})' if context else ''} : "
            f"{len(expected)} colonnes attendues"
            + (" (entrée modèle, adresses IP exclues)" if model_input else "")
            + "."
        )
        raise FlowFeatureError("\n".join([header] + problems))


def verify_dataset_schema(csv_path: str) -> bool:
    """
    Utilitaire de maintenance : confronte NETFLOW_V1_COLUMNS (figé
    ci-dessus) à l'en-tête réel du CSV NF-CSE-CIC-IDS2018 v1. À lancer
    après tout changement de jeu de données.
    """
    header = pd.read_csv(csv_path, nrows=0)
    actual = list(header.columns)
    label_columns = [c for c in actual if c in ("Label", "Attack")]
    feature_columns = [c for c in actual if c not in label_columns]

    print(f"En-tête du jeu de données ({len(actual)} colonnes) : {actual}")
    print(f"Colonnes d'étiquetage détectées : {label_columns}")

    if feature_columns == NETFLOW_V1_COLUMNS:
        print("OK : NETFLOW_V1_COLUMNS correspond exactement au jeu de données (noms et ordre).")
        return True

    print("DÉRIVE entre flow_feature_extractor.NETFLOW_V1_COLUMNS et le jeu de données :")
    print("  Absentes du jeu de données :", [c for c in NETFLOW_V1_COLUMNS if c not in feature_columns])
    print("  Absentes du module        :", [c for c in feature_columns if c not in NETFLOW_V1_COLUMNS])
    if set(feature_columns) == set(NETFLOW_V1_COLUMNS):
        print("  (mêmes colonnes, ordre différent)")
        print("  ordre jeu de données :", feature_columns)
    return False


def verify_l7_proto_map(csv_path: str, chunksize: int = 2_000_000,
                        min_share: float = 0.95) -> bool:
    """
    Utilitaire de maintenance : reconfronte L7_PROTO_BY_APP_PROTO au jeu
    de données. Pour chaque correspondance figée (app_proto -> valeur
    L7), mesure la proportion des flux portant cette valeur dont le port
    applicatif de référence apparaît en source OU en destination.

    Le test porte sur les DEUX ports, et c'est essentiel : le jeu contient
    des flux enregistrés dans le sens serveur -> client, où le port
    applicatif est le port SOURCE et le port destination un port éphémère.
    Ne regarder que L4_DST_PORT fait chuter la part apparente de RDP
    (L7_PROTO=88) de 100% à 5,6% et produit un faux écart -- erreur
    commise puis corrigée lors de la dérivation initiale, consignée ici
    pour qu'elle ne soit pas refaite.

    Seuil de confirmation : min_share (95% par défaut). Les 13 entrées
    figées se situent entre 95,8% et 100%.
    """
    values_to_port = {}
    for app_proto, value in L7_PROTO_BY_APP_PROTO.items():
        ports = [p for p, name in L7_REFERENCE_PORTS.items() if name == app_proto]
        if not ports:
            raise FlowFeatureError(
                f"Incohérence interne : {app_proto!r} figure dans "
                f"L7_PROTO_BY_APP_PROTO mais pas dans L7_REFERENCE_PORTS."
            )
        values_to_port[int(value)] = (ports[0], app_proto)

    matched = {v: 0 for v in values_to_port}
    seen = {v: 0 for v in values_to_port}
    total = 0

    for chunk in pd.read_csv(
        csv_path, usecols=["L4_SRC_PORT", "L4_DST_PORT", "L7_PROTO"],
        dtype={"L4_SRC_PORT": "int32", "L4_DST_PORT": "int32", "L7_PROTO": "float32"},
        chunksize=chunksize,
    ):
        total += len(chunk)
        master = chunk["L7_PROTO"].astype("int32")
        for value, (port, _) in values_to_port.items():
            subset = chunk[master == value]
            if subset.empty:
                continue
            seen[value] += len(subset)
            matched[value] += int(
                ((subset["L4_DST_PORT"] == port) | (subset["L4_SRC_PORT"] == port)).sum()
            )

    print(f"Lignes analysées : {total}")
    print(f"{'app_proto':<10} {'L7 figé':>8} {'port réf.':>10} {'flux':>10} "
          f"{'part src|dst':>13}  verdict")
    all_ok = True
    for value in sorted(values_to_port):
        port, app_proto = values_to_port[value]
        share = matched[value] / seen[value] if seen[value] else 0.0
        ok = seen[value] > 0 and share >= min_share
        all_ok = all_ok and ok
        print(f"{app_proto:<10} {value:>8} {port:>10} {seen[value]:>10} "
              f"{share:>12.1%}  {'OK' if ok else 'ÉCART'}")

    print("\nOK : la table figée correspond au jeu de données."
          if all_ok else
          f"\nÉCART (seuil {min_share:.0%}) — corriger L7_PROTO_BY_APP_PROTO "
          f"avant tout entraînement.")
    return all_ok


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[2])
    parser.add_argument("--eve", default="/var/log/suricata/eve.json",
                        help="chemin du eve.json Suricata")
    parser.add_argument("--since", help='borne basse de timestamp (ex. "2026-08-31T23:00")')
    parser.add_argument("--until", help='borne haute de timestamp (ex. "2026-08-31T23:59")')
    parser.add_argument("--out", help="chemin CSV de sortie (validé avant écriture)")
    parser.add_argument("--verify-schema", metavar="CSV",
                        help="confronte le schéma figé à l'en-tête d'un CSV NF-*")
    parser.add_argument("--verify-l7", metavar="CSV",
                        help="redérive et confronte la table L7_PROTO depuis un CSV NF-*")
    args = parser.parse_args()

    if args.verify_schema:
        raise SystemExit(0 if verify_dataset_schema(args.verify_schema) else 1)

    if args.verify_l7:
        raise SystemExit(0 if verify_l7_proto_map(args.verify_l7) else 1)

    df, stats = extract_flow_features(iter_flow_events(args.eve, args.since, args.until))
    print(stats.summary())
    print()
    if df.empty:
        print("Aucun flux retenu — rien à écrire.")
        raise SystemExit(1)

    print(df.head(10).to_string(index=False))
    print(f"\n{len(df)} flux au schéma NetFlow v1.")

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        df.to_csv(args.out, index=False)
        print(f"Écrit : {args.out}")
