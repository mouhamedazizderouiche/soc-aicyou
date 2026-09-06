"""
live_data_collector.py

Construit un jeu de données d'entraînement étiqueté directement sur le
schéma du pipeline live (feature_extractor.py), pour combler l'écart
architectural documenté le 15/08/2026 (voir feature_schema.py,
docs/journal-technique.md) : le moteur IA n'a jamais été entraîné ni
validé sur des données réellement produites par Suricata/Wazuh, seulement
sur NSL-KDD.

Principe d'étiquetage : les 5 règles personnalisées déjà validées en
conditions réelles (voir docs/architecture.md, section 6) servent de
vérité terrain. Une fenêtre de features est étiquetée avec la tactique
correspondante SI ET SEULEMENT SI une alerte de la règle associée a été
détectée pour cet agent dans cette même fenêtre temporelle :

    sid 9000001 / règle Wazuh 100012 -> Reconnaissance
    sid 9000002 / règle Wazuh 100013 -> Reconnaissance
    sid 9000003 / règle Wazuh 100014 -> Impact
    règle Wazuh 100010 / 100011      -> InitialAccess_CredentialAccess

Toute fenêtre ne déclenchant aucune de ces règles est étiquetée "Normal"
(background). PrivilegeEscalation est délibérément absent : aucune règle
équivalente n'existe encore pour cette tactique (voir plan de correction
séparé, approche par règle plutôt que par ce collecteur).

Design :
- Idempotent / reprenable : un checkpoint (par agent + window_start) évite
  les doublons entre exécutions successives, même pattern que collector.py.
- Validation de schéma explicite avant écriture (feature_schema.py) : une
  dérive de colonnes dans feature_extractor.py serait détectée ici, pas
  découverte silencieusement des semaines plus tard au moment de
  l'entraînement.
- Ambiguïté traitée explicitement, jamais résolue par défaut silencieux :
  une fenêtre où plusieurs groupes de tactiques différents déclenchent en
  même temps est écartée du jeu d'entraînement et journalisée à part pour
  revue humaine, plutôt que d'assigner arbitrairement l'une des tactiques.
"""

import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone

import pandas as pd

from wazuh_client import WazuhIndexerClient
from normalizer import normalize_batch
from feature_extractor import extract_features
from feature_schema import LIVE_PIPELINE_FEATURE_COLUMNS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("live_data_collector")

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
LABELED_DATASET_PATH = os.path.join(DATA_DIR, "live_training_data.jsonl")
AMBIGUOUS_LOG_PATH = os.path.join(DATA_DIR, "live_training_ambiguous.jsonl")
CHECKPOINT_PATH = os.path.join(DATA_DIR, "live_training_checkpoint.json")

RULE_TO_TACTIC = {
    "100012": "Reconnaissance",
    "100013": "Reconnaissance",
    "100014": "Impact",
    "100010": "InitialAccess_CredentialAccess",
    "100011": "InitialAccess_CredentialAccess",
}

WINDOW_MINUTES = 1


def load_checkpoint() -> set:
    if os.path.exists(CHECKPOINT_PATH):
        with open(CHECKPOINT_PATH) as f:
            return set(tuple(x) for x in json.load(f))
    return set()


def save_checkpoint(processed: set) -> None:
    with open(CHECKPOINT_PATH, "w") as f:
        json.dump(sorted(list(processed)), f)


def determine_window_labels(normalized_alerts: list) -> dict:
    window_tactics = defaultdict(set)

    for alert in normalized_alerts:
        rule_id = str(alert.get("rule_id", ""))
        tactic = RULE_TO_TACTIC.get(rule_id)
        if tactic is None:
            continue

        agent = alert.get("agent_name", "unknown")
        ts_raw = alert.get("timestamp")
        if not ts_raw:
            continue
        try:
            ts = pd.to_datetime(ts_raw, utc=True)
        except (ValueError, TypeError):
            continue

        window_start = ts.floor(f"{WINDOW_MINUTES}min").isoformat()
        window_tactics[(agent, window_start)].add(tactic)

    return window_tactics


def label_features(features_df: pd.DataFrame, window_tactics: dict) -> pd.DataFrame:
    labels = []
    ambiguous_rows = []

    for _, row in features_df.iterrows():
        agent = row.get("agent_name", "unknown")
        window_start_raw = row.get("window_start")
        try:
            window_start = pd.to_datetime(window_start_raw, utc=True).isoformat()
        except (ValueError, TypeError):
            labels.append(None)
            continue

        tactics_here = window_tactics.get((agent, window_start), set())

        if len(tactics_here) == 0:
            labels.append("Normal")
        elif len(tactics_here) == 1:
            labels.append(next(iter(tactics_here)))
        else:
            logger.warning(
                "Fenêtre ambiguë exclue : agent=%s window=%s tactiques=%s",
                agent, window_start, tactics_here,
            )
            labels.append(None)
            ambiguous_rows.append({
                "agent_name": agent,
                "window_start": window_start,
                "conflicting_tactics": sorted(tactics_here),
                "logged_at": datetime.now(timezone.utc).isoformat(),
            })

    features_df = features_df.copy()
    features_df["label"] = labels

    if ambiguous_rows:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(AMBIGUOUS_LOG_PATH, "a") as f:
            for r in ambiguous_rows:
                f.write(json.dumps(r) + "\n")
        logger.warning("%d fenêtre(s) ambiguë(s) journalisée(s) dans %s",
                        len(ambiguous_rows), AMBIGUOUS_LOG_PATH)

    return features_df[features_df["label"].notna()]


def validate_and_save(labeled_df: pd.DataFrame) -> int:
    feature_cols = [c for c in labeled_df.columns if c != "label"]
    missing = set(LIVE_PIPELINE_FEATURE_COLUMNS) - set(feature_cols)
    unexpected = set(feature_cols) - set(LIVE_PIPELINE_FEATURE_COLUMNS)

    if missing or unexpected:
        raise RuntimeError(
            f"Dérive de schéma détectée entre feature_extractor.py et "
            f"feature_schema.py -- ARRÊT avant écriture pour éviter de "
            f"corrompre le jeu d'entraînement.\n"
            f"Colonnes manquantes : {sorted(missing)}\n"
            f"Colonnes inattendues : {sorted(unexpected)}\n"
            f"Action requise : mettre à jour LIVE_PIPELINE_FEATURE_COLUMNS "
            f"dans feature_schema.py pour refléter le schéma réel."
        )

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(LABELED_DATASET_PATH, "a") as f:
        for _, row in labeled_df.iterrows():
            record = row.to_dict()
            for k, v in record.items():
                if isinstance(v, (pd.Timestamp, datetime)):
                    record[k] = v.isoformat()
            f.write(json.dumps(record, default=str) + "\n")

    return len(labeled_df)


def run_once(alert_batch_size: int = 500) -> None:
    checkpoint = load_checkpoint()

    client = WazuhIndexerClient()
    result = client.search_alerts(size=alert_batch_size)
    hits = result["hits"]["hits"]

    if not hits:
        logger.info("Aucune alerte récupérée -- rien à traiter.")
        return

    normalized = normalize_batch(hits)
    window_tactics = determine_window_labels(normalized)

    features_df = extract_features(normalized, window_minutes=WINDOW_MINUTES)
    if features_df.empty:
        logger.info("Aucune fenêtre de features produite -- rien à traiter.")
        return

    labeled_df = label_features(features_df, window_tactics)

    def _key(row):
        try:
            ws = pd.to_datetime(row["window_start"], utc=True).isoformat()
        except (ValueError, TypeError):
            ws = str(row["window_start"])
        return (row.get("agent_name", "unknown"), ws)

    labeled_df["_ckpt_key"] = labeled_df.apply(_key, axis=1)
    new_rows = labeled_df[~labeled_df["_ckpt_key"].apply(lambda k: k in checkpoint)]
    new_rows = new_rows.drop(columns=["_ckpt_key"])

    if new_rows.empty:
        logger.info("Toutes les fenêtres de ce batch ont déjà été traitées.")
        return

    saved_count = validate_and_save(new_rows)

    for _, row in labeled_df.iterrows():
        checkpoint.add(_key(row))
    save_checkpoint(checkpoint)

    label_counts = new_rows["label"].value_counts().to_dict()
    logger.info("%d nouvelle(s) fenêtre(s) sauvegardée(s). Répartition : %s",
                saved_count, label_counts)


def print_dataset_summary() -> None:
    if not os.path.exists(LABELED_DATASET_PATH):
        print("Aucune donnée collectée pour le moment.")
        return

    rows = []
    with open(LABELED_DATASET_PATH) as f:
        for line in f:
            rows.append(json.loads(line))

    df = pd.DataFrame(rows)
    print(f"\n=== Jeu de données d'entraînement live -- {len(df)} fenêtres ===\n")
    print(df["label"].value_counts().to_string())
    print()


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "summary":
        print_dataset_summary()
    else:
        run_once()
        print_dataset_summary()
