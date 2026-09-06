"""
netflow_transfer_diagnostics.py

Diagnostics complémentaires du test de transfert : balayage de seuil,
AUC, importance des features, et recouvrement des ports d'attaque entre
les deux domaines.

Écrit après que netflow_transfer_test.py a rendu un rappel nul sur les
trois classes d'attaque. Un zéro aussi net appelle deux questions qu'on
ne peut pas laisser ouvertes avant de conclure :
  1. Est-ce un bug de mon pipeline d'inférence, ou un vrai résultat ?
     -> control_source_domain() fait passer des données du jeu SOURCE par
        le même chemin de code. Si le rappel y est élevé, le chemin est
        correct.
  2. L'échec est-il propre au seuil 0,5, ou total ?
     -> threshold_sweep() et l'AUC, qui ne dépend d'aucun seuil.
"""

import argparse
import collections
import json
import os

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import average_precision_score, roc_auc_score

from flow_feature_extractor import NETFLOW_V1_MODEL_COLUMNS

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "netflow")
CONTROL_CLASSES = ["SSH-Bruteforce", "DoS attacks-Hulk", "DoS attacks-GoldenEye",
                   "DoS attacks-Slowloris", "DDoS attacks-LOIC-HTTP",
                   "FTP-BruteForce", "Benign"]


def _sample_source(csv_path: str, classes: list, per_class: int) -> pd.DataFrame:
    """Échantillon du jeu source, `per_class` lignes par classe demandée."""
    buckets = collections.defaultdict(list)
    usecols = NETFLOW_V1_MODEL_COLUMNS + ["Label", "Attack"]
    for chunk in pd.read_csv(csv_path, usecols=usecols, chunksize=500_000):
        for cls in classes:
            if sum(len(d) for d in buckets[cls]) < per_class:
                group = chunk[chunk["Attack"] == cls]
                if len(group):
                    buckets[cls].append(group.head(per_class))
        if all(sum(len(d) for d in buckets[c]) >= per_class for c in classes):
            break
    return pd.concat([pd.concat(v).head(per_class) for v in buckets.values()],
                      ignore_index=True)


def control_source_domain(model, csv_path: str, per_class: int = 2000) -> dict:
    """
    CONTRÔLE : le même modèle, le même chemin de code, mais sur des flux
    du jeu source. Sert à distinguer « mon pipeline est cassé » de « le
    modèle ne transfère pas ».
    """
    src = _sample_source(csv_path, CONTROL_CLASSES, per_class)
    proba = model.predict_proba(src[NETFLOW_V1_MODEL_COLUMNS])[:, 1]
    pred = (proba >= 0.5).astype(int)

    print("=== CONTRÔLE — jeu SOURCE via le chemin de code du test de transfert ===")
    print(f"{'classe source':<26} {'n':>6} {'rappel':>8} {'proba moy':>11}")
    out = {}
    for cls in sorted(src["Attack"].unique()):
        mask = (src["Attack"] == cls).to_numpy()
        rate = float((pred[mask] == 0).mean()) if cls == "Benign" \
            else float((pred[mask] == 1).mean())
        out[cls] = {"n": int(mask.sum()), "rate": rate,
                    "mean_proba": float(proba[mask].mean())}
        label = "non alerté" if cls == "Benign" else "rappel"
        print(f"{cls:<26} {int(mask.sum()):>6} {rate:>8.4f} "
              f"{proba[mask].mean():>11.4f}   ({label})")
    return out


def threshold_sweep(proba, truth, thresholds) -> dict:
    """
    Rappel par classe en abaissant le seuil. Un modèle simplement mal
    calibré retrouve du rappel quand on descend ; un modèle qui n'a rien
    appris de transférable n'en retrouve qu'en alertant sur tout, ce que
    la colonne FPR rend visible.
    """
    print("\n=== Balayage de seuil ===")
    print(f"{'seuil':>8} {'recon':>8} {'DoS':>8} {'brute':>8} {'FPR bénin':>11}")
    rows = {}
    for t in thresholds:
        pred = (proba >= t).astype(int)
        recalls = {c: float((pred[truth == c] == 1).mean())
                   for c in ("Reconnaissance", "DoS", "BruteForce")}
        fpr = float((pred[truth == "Benign"] == 1).mean())
        rows[str(t)] = {**recalls, "false_positive_rate": fpr}
        print(f"{t:>8.2f} {recalls['Reconnaissance']:>8.4f} {recalls['DoS']:>8.4f} "
              f"{recalls['BruteForce']:>8.4f} {fpr:>11.4f}")
    return rows


def port_overlap(live: pd.DataFrame, csv_path: str, per_class: int = 6000) -> dict:
    """
    Recouvrement des ports de destination d'attaque entre les deux
    domaines. L4_DST_PORT pèse lourd dans la décision du modèle : si les
    ports attaqués ne se recouvrent pas, le modèle n'a aucun appui.
    """
    buckets = collections.defaultdict(list)
    usecols = NETFLOW_V1_MODEL_COLUMNS + ["Label", "Attack"]
    for chunk in pd.read_csv(csv_path, usecols=usecols, chunksize=500_000):
        for lab in (0, 1):
            group = chunk[chunk["Label"] == lab]
            if len(group) and sum(len(d) for d in buckets[lab]) < 10 * per_class:
                buckets[lab].append(group.head(per_class))
        if all(sum(len(d) for d in buckets[l]) >= 10 * per_class for l in (0, 1)):
            break
    src = pd.concat([pd.concat(v) for v in buckets.values()], ignore_index=True)

    src_ports = set(src[src["Label"] == 1]["L4_DST_PORT"])
    live_attacks = live[live["Label"] == 1]
    live_ports = set(live_attacks["L4_DST_PORT"])
    covered = float(live_attacks["L4_DST_PORT"].isin(src_ports).mean())

    print("\n=== Recouvrement des ports d'attaque entre domaines ===")
    print(f"  ports d'attaque SOURCE : {len(src_ports)}   LIVE : {len(live_ports)}   "
          f"communs : {len(src_ports & live_ports)}")
    print(f"  part des flux d'attaque live dont le port a été vu en attaque "
          f"à l'entraînement : {covered:.1%}")
    return {"n_source_ports": len(src_ports), "n_live_ports": len(live_ports),
            "n_common": len(src_ports & live_ports),
            "live_attack_flows_on_known_attack_port": covered}


def main():
    parser = argparse.ArgumentParser(description="Diagnostics du test de transfert.")
    parser.add_argument("--live", default=os.path.join(DATA_DIR, "live_flows_labelled.csv"))
    parser.add_argument("--train-csv", default=os.path.join(DATA_DIR, "NF-CSE-CIC-IDS2018.csv"))
    parser.add_argument("--model-dir", default=DATA_DIR)
    parser.add_argument("--out", default=os.path.join(DATA_DIR, "netflow_transfer_diagnostics.json"))
    args = parser.parse_args()

    live = pd.read_csv(args.live)
    model = xgb.XGBClassifier()
    model.load_model(os.path.join(args.model_dir, "netflow_xgboost_binary.json"))

    control = control_source_domain(model, args.train_csv)

    proba = model.predict_proba(live[NETFLOW_V1_MODEL_COLUMNS])[:, 1]
    truth = live["Attack"].to_numpy()
    y = live["Label"].to_numpy()

    sweep = threshold_sweep(proba, truth, [0.5, 0.3, 0.2, 0.1, 0.05, 0.03, 0.02, 0.01])

    auc = float(roc_auc_score(y, proba))
    ap = float(average_precision_score(y, proba))
    print(f"\n=== Métriques indépendantes du seuil ===")
    print(f"  AUC-ROC : {auc:.4f}   (0,5 = hasard ; en dessous = anti-corrélation)")
    print(f"  AUC-PR  : {ap:.4f}   (base = {y.mean():.4f})")
    per_class_auc = {}
    print("  AUC-ROC par classe d'attaque, contre les bénins :")
    for cls in ("Reconnaissance", "DoS", "BruteForce"):
        mask = (truth == cls) | (truth == "Benign")
        value = float(roc_auc_score((truth[mask] != "Benign").astype(int), proba[mask]))
        per_class_auc[cls] = value
        print(f"    {cls:<16} {value:.4f}")

    importances = dict(zip(NETFLOW_V1_MODEL_COLUMNS,
                            (float(v) for v in model.feature_importances_)))
    print("\n=== Importance des features (modèle binaire) ===")
    for k, v in sorted(importances.items(), key=lambda kv: -kv[1]):
        print(f"  {k:<30} {v:.4f}")

    overlap = port_overlap(live, args.train_csv)

    report = {
        "control_source_domain": control,
        "threshold_sweep": sweep,
        "auc_roc": auc, "auc_pr": ap, "positive_rate": float(y.mean()),
        "auc_roc_per_class": per_class_auc,
        "feature_importances": importances,
        "attack_port_overlap": overlap,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\nRapport écrit : {args.out}")


if __name__ == "__main__":
    main()
