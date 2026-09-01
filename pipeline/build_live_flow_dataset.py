"""
build_live_flow_dataset.py

Construit le jeu de test « trafic réel » du test de transfert
inter-domaine : parcourt eve.json, retient les flux couverts par une
fenêtre de netflow_ground_truth, les convertit au schéma NetFlow v1 via
flow_feature_extractor, et écrit un CSV étiqueté.

Le résultat n'est PAS un jeu d'entraînement : il sert uniquement à
mesurer si un modèle entraîné sur NF-CSE-CIC-IDS2018 généralise au
trafic de ce réseau. Aucun flux de ce fichier ne doit être utilisé pour
entraîner ou régler un seuil, sous peine de rendre la mesure invalide.
"""

import argparse
import logging
import os

import pandas as pd

from flow_feature_extractor import (
    NETFLOW_V1_COLUMNS,
    ExtractionStats,
    flow_record_to_features,
    iter_flow_events,
    validate_netflow_v1_schema,
)
from netflow_ground_truth import label_flow

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("build_live_flow_dataset")

DEFAULT_EVE = "/var/log/suricata/eve.json"
DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "data", "netflow", "live_flows_labelled.csv")


def build(eve_path: str) -> tuple:
    """
    Retourne (DataFrame étiqueté, ExtractionStats). Le DataFrame porte
    les 12 colonnes NetFlow v1 plus une colonne `Attack` (classe de
    vérité terrain) et `Label` (0 bénin / 1 attaque), pour coller aux
    conventions de nommage de NF-CSE-CIC-IDS2018.
    """
    stats = ExtractionStats()
    rows, labels = [], []

    for event in iter_flow_events(eve_path):
        truth = label_flow(event)
        if truth is None:
            continue  # hors de toute fenêtre de vérité terrain
        stats.seen += 1
        features = flow_record_to_features(event, stats)
        if features is None:
            continue
        rows.append(features)
        labels.append(truth)

    df = pd.DataFrame(rows, columns=NETFLOW_V1_COLUMNS)
    validate_netflow_v1_schema(df, context="build_live_flow_dataset")

    df["Attack"] = labels
    df["Label"] = (df["Attack"] != "Benign").astype(int)
    return df, stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Construit le jeu live étiqueté (NetFlow v1).")
    parser.add_argument("--eve", default=DEFAULT_EVE)
    parser.add_argument("--out", default=DEFAULT_OUT)
    args = parser.parse_args()

    df, stats = build(args.eve)

    print(stats.summary())
    print()
    if df.empty:
        print("ÉCHEC : aucun flux étiqueté produit. Vérifier les fenêtres de "
              "netflow_ground_truth.py et la plage temporelle de eve.json.")
        raise SystemExit(1)

    print("Distribution des classes de vérité terrain :")
    for cls, count in df["Attack"].value_counts().items():
        print(f"  {cls:<16} {count:6d}  ({count / len(df):.1%})")
    print(f"\nTotal : {len(df)} flux étiquetés "
          f"({df['Label'].sum()} attaques / {(df['Label'] == 0).sum()} bénins)")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    df.to_csv(args.out, index=False)
    print(f"\nÉcrit : {args.out}")
