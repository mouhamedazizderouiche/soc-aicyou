"""
train_netflow_model.py

Entraîne les modèles du chemin d'analyse « NetFlow » sur
NF-CSE-CIC-IDS2018 v1 (8 392 401 flux, 12,14% d'attaques).

Deux modèles, comme sur le chemin NSL-KDD existant :
  - binaire      : bénin / attaque -> alimente le score de risque
  - multi-classe : catégorie d'attaque -> alimente la correspondance MITRE

Et deux algorithmes :
  - Extra Trees, l'algorithme retenu par Sarhan et al. sur ces jeux :
    sert de point de comparaison avec la littérature.
  - XGBoost, pour rester cohérent avec le reste du projet (risk_scorer,
    tactic_classifier) et parce que c'est lui qui sera déployé.

CONTRAINTE MATÉRIELLE, ET SON EFFET SUR LES RÉSULTATS
-----------------------------------------------------
La VM dispose d'environ 2 Go de RAM utilisable. Un Extra Trees à 100
arbres sur 5,9 M de lignes n'y tient pas. Extra Trees est donc entraîné
sur un sous-échantillon stratifié (--et-sample, 1 M de lignes par
défaut) tandis que XGBoost, dont l'empreinte mémoire avec
tree_method="hist" est bornée par les histogrammes et non par le nombre
de lignes, est entraîné sur la totalité du jeu d'entraînement. Les deux
chiffres ne sont donc PAS strictement comparables entre eux : le
sous-échantillonnage est signalé dans le rapport produit.

REPRISE APRÈS INTERRUPTION
--------------------------
Le rapport JSON est réécrit après CHAQUE modèle, pas une seule fois à la
fin, et --resume réutilise un modèle déjà présent sur disque au lieu de
le réentraîner. Motivation concrète : cette VM a été interrompue deux
fois en cours d'entraînement (redémarrage), perdant à chaque fois les
métriques déjà calculées alors que les modèles, eux, étaient écrits.
Les résultats restent identiques d'une reprise à l'autre : random_state
est fixé et le découpage train/test en dépend seul.

MÉTRIQUES
---------
Le jeu est déséquilibré (87,86% bénin). L'exactitude globale n'est
jamais rapportée seule : le rapport donne précision/rappel/F1 PAR
CLASSE, ce qui est la seule lecture honnête sur ce type de distribution.
"""

import argparse
import json
import logging
import os
import time

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from flow_feature_extractor import NETFLOW_V1_MODEL_COLUMNS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_netflow_model")

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "netflow")
RANDOM_STATE = 42

# dtypes explicites : sans cela pandas infère int64/float64 partout et le
# jeu complet ne tient pas dans la mémoire disponible.
READ_DTYPES = {
    "L4_SRC_PORT": "int32",
    "L4_DST_PORT": "int32",
    "PROTOCOL": "int16",
    "L7_PROTO": "float32",
    "IN_BYTES": "int64",
    "OUT_BYTES": "int64",
    "IN_PKTS": "int32",
    "OUT_PKTS": "int32",
    "TCP_FLAGS": "int32",
    "FLOW_DURATION_MILLISECONDS": "int64",
    "Label": "int8",
    "Attack": "category",
}


def load_dataset(csv_path: str) -> pd.DataFrame:
    """
    Charge le jeu en ne lisant que les colonnes utiles. Les adresses IP
    sont volontairement écartées dès la lecture : elles sont propres au
    banc d'essai CIC et un modèle qui les utilise mémorise ce réseau au
    lieu d'apprendre un comportement (voir flow_feature_extractor,
    NETFLOW_V1_MODEL_COLUMNS).
    """
    usecols = NETFLOW_V1_MODEL_COLUMNS + ["Label", "Attack"]
    logger.info("Lecture de %s (colonnes : %s)", csv_path, usecols)
    df = pd.read_csv(csv_path, usecols=usecols, dtype=READ_DTYPES)
    logger.info("Chargé : %d lignes, %.0f Mo en mémoire",
                len(df), df.memory_usage(deep=True).sum() / 1e6)
    return df


def per_class_report(y_true, y_pred, labels, title: str) -> dict:
    """
    Rapport précision/rappel/F1 par classe. L'exactitude globale est
    affichée mais explicitement encadrée comme non informative sur un jeu
    déséquilibré -- elle ne doit jamais être citée seule.
    """
    report = classification_report(
        y_true, y_pred, labels=list(range(len(labels))), target_names=labels,
        digits=4, zero_division=0, output_dict=True,
    )
    print(f"\n=== {title} ===")
    print(f"{'classe':<18} {'précision':>10} {'rappel':>10} {'F1':>10} {'support':>10}")
    for name in labels:
        r = report[name]
        print(f"{name:<18} {r['precision']:>10.4f} {r['recall']:>10.4f} "
              f"{r['f1-score']:>10.4f} {int(r['support']):>10d}")
    print(f"{'macro avg':<18} {report['macro avg']['precision']:>10.4f} "
          f"{report['macro avg']['recall']:>10.4f} {report['macro avg']['f1-score']:>10.4f}")
    print(f"(exactitude globale : {report['accuracy']:.4f} — non informative seule, "
          f"jeu déséquilibré)")
    return report


def save_report(results: dict, path: str) -> None:
    """
    Écrit le rapport de façon atomique (fichier temporaire puis
    remplacement) : une interruption pendant l'écriture laisse le rapport
    précédent intact plutôt qu'un JSON tronqué.
    """
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    logger.info("Rapport mis à jour : %s", path)


def main():
    parser = argparse.ArgumentParser(description="Entraîne les modèles NetFlow v1.")
    parser.add_argument("--csv", default=os.path.join(DATA_DIR, "NF-CSE-CIC-IDS2018.csv"))
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--et-sample", type=int, default=1_000_000,
                        help="taille du sous-échantillon stratifié pour Extra Trees "
                             "(contrainte RAM ; 0 = jeu complet)")
    parser.add_argument("--et-estimators", type=int, default=50)
    parser.add_argument("--xgb-estimators", type=int, default=200)
    parser.add_argument("--n-jobs", type=int, default=4,
                        help="parallélisme. Chaque worker Extra Trees duplique une "
                             "part du jeu en mémoire. Sur cette VM (2,2 Go utilisables, "
                             "8 cœurs), n_jobs=-1 a été mesuré à 58%% de la RAM totale "
                             "et encore en hausse ; la marge était trop faible pour "
                             "être fiable, d'où ce plafond à 4. Ce n'est pas un "
                             "dépassement constaté, c'est une marge insuffisante.")
    parser.add_argument("--out-dir", default=DATA_DIR)
    parser.add_argument("--resume", action="store_true",
                        help="réutilise les modèles déjà présents sur disque "
                             "au lieu de les réentraîner (les métriques sont "
                             "recalculées dans tous les cas)")
    args = parser.parse_args()

    df = load_dataset(args.csv)

    print("\n=== Distribution du jeu complet ===")
    counts = df["Attack"].value_counts()
    for cls, n in counts.items():
        print(f"  {cls:<18} {n:9d}  ({n / len(df):.2%})")
    print(f"  {'TOTAL':<18} {len(df):9d}")

    X = df[NETFLOW_V1_MODEL_COLUMNS]
    y_bin = df["Label"].to_numpy()
    attack_encoder = LabelEncoder()
    y_multi = attack_encoder.fit_transform(df["Attack"].astype(str))
    class_names = list(attack_encoder.classes_)

    X_train, X_test, ybin_train, ybin_test, ymul_train, ymul_test = train_test_split(
        X, y_bin, y_multi, test_size=args.test_size,
        random_state=RANDOM_STATE, stratify=y_multi,
    )
    del df
    logger.info("Découpage : %d entraînement / %d test", len(X_train), len(X_test))

    results = {
        "dataset": os.path.basename(args.csv),
        "n_jobs": args.n_jobs,
        "n_total": int(len(X_train) + len(X_test)),
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "features": NETFLOW_V1_MODEL_COLUMNS,
        "class_names": class_names,
        "random_state": RANDOM_STATE,
        "models": {},
    }
    os.makedirs(args.out_dir, exist_ok=True)
    report_path = os.path.join(args.out_dir, "netflow_training_report.json")

    # ---------------- Extra Trees (référence littérature) -------------
    if args.et_sample and args.et_sample < len(X_train):
        idx, _ = train_test_split(
            np.arange(len(X_train)), train_size=args.et_sample,
            random_state=RANDOM_STATE, stratify=ymul_train,
        )
        Xet, yet = X_train.iloc[idx], ymul_train[idx]
        subsampled = True
    else:
        Xet, yet = X_train, ymul_train
        subsampled = False
    logger.info("Extra Trees : entraînement sur %d lignes (sous-échantillonné=%s)",
                len(Xet), subsampled)

    et_path = os.path.join(args.out_dir, "netflow_extratrees_multiclass.pkl")
    if args.resume and os.path.exists(et_path):
        logger.info("Reprise : Extra Trees rechargé depuis %s (pas de réentraînement)", et_path)
        et = joblib.load(et_path)
        et_time = None
    else:
        t0 = time.time()
        et = ExtraTreesClassifier(
            n_estimators=args.et_estimators, n_jobs=args.n_jobs,
            random_state=RANDOM_STATE, class_weight="balanced_subsample",
        )
        et.fit(Xet, yet)
        et_time = time.time() - t0
        logger.info("Extra Trees entraîné en %.1f s", et_time)

    et_pred = et.predict(X_test)
    et_report = per_class_report(
        ymul_test, et_pred, class_names,
        f"Extra Trees — multi-classe (entraîné sur {len(Xet)} lignes"
        f"{', sous-échantillon stratifié' if subsampled else ''})",
    )
    results["models"]["extra_trees_multiclass"] = {
        "n_train_used": int(len(Xet)),
        "subsampled": subsampled,
        "n_estimators": args.et_estimators,
        "train_seconds": round(et_time, 1) if et_time is not None else None,
        "reloaded_from_disk": et_time is None,
        "per_class": {k: et_report[k] for k in class_names},
        "macro_avg": et_report["macro avg"],
        "accuracy": et_report["accuracy"],
    }
    if et_time is not None:
        joblib.dump(et, et_path, compress=3)
    del et
    save_report(results, report_path)

    # ---------------- XGBoost binaire (score de risque) ---------------
    bin_path = os.path.join(args.out_dir, "netflow_xgboost_binary.json")
    xgb_bin = xgb.XGBClassifier()
    if args.resume and os.path.exists(bin_path):
        logger.info("Reprise : XGBoost binaire rechargé depuis %s", bin_path)
        xgb_bin.load_model(bin_path)
        bin_time = None
    else:
        t0 = time.time()
        xgb_bin = xgb.XGBClassifier(
            n_estimators=args.xgb_estimators, max_depth=8, learning_rate=0.1,
            tree_method="hist", n_jobs=args.n_jobs, random_state=RANDOM_STATE,
            eval_metric="logloss",
            # Rééquilibrage : 87,86% de bénins, sans quoi le modèle optimise
            # l'exactitude en ignorant la classe minoritaire.
            scale_pos_weight=float((ybin_train == 0).sum() / max((ybin_train == 1).sum(), 1)),
        )
        xgb_bin.fit(X_train, ybin_train)
        bin_time = time.time() - t0
        logger.info("XGBoost binaire entraîné en %.1f s", bin_time)

    bin_pred = xgb_bin.predict(X_test)
    bin_report = per_class_report(ybin_test, bin_pred, ["Benign", "Attack"],
                                   "XGBoost — binaire (jeu d'entraînement complet)")
    results["models"]["xgboost_binary"] = {
        "n_train_used": int(len(X_train)),
        "n_estimators": args.xgb_estimators,
        "train_seconds": round(bin_time, 1) if bin_time is not None else None,
        "reloaded_from_disk": bin_time is None,
        "per_class": {k: bin_report[k] for k in ["Benign", "Attack"]},
        "accuracy": bin_report["accuracy"],
    }
    if bin_time is not None:
        xgb_bin.save_model(bin_path)
    del xgb_bin
    save_report(results, report_path)

    # ---------------- XGBoost multi-classe (tactique) -----------------
    mul_path = os.path.join(args.out_dir, "netflow_xgboost_multiclass.json")
    xgb_mul = xgb.XGBClassifier()
    if args.resume and os.path.exists(mul_path):
        logger.info("Reprise : XGBoost multi-classe rechargé depuis %s", mul_path)
        xgb_mul.load_model(mul_path)
        mul_time = None
    else:
        t0 = time.time()
        xgb_mul = xgb.XGBClassifier(
            n_estimators=args.xgb_estimators, max_depth=8, learning_rate=0.1,
            tree_method="hist", n_jobs=args.n_jobs, random_state=RANDOM_STATE,
            objective="multi:softprob", num_class=len(class_names),
        )
        xgb_mul.fit(X_train, ymul_train)
        mul_time = time.time() - t0
        logger.info("XGBoost multi-classe entraîné en %.1f s", mul_time)

    mul_pred = xgb_mul.predict(X_test)
    mul_report = per_class_report(ymul_test, mul_pred, class_names,
                                   "XGBoost — multi-classe (jeu d'entraînement complet)")
    print("\nMatrice de confusion (lignes = vérité, colonnes = prédiction) :")
    cm = confusion_matrix(ymul_test, mul_pred, labels=list(range(len(class_names))))
    print(pd.DataFrame(cm, index=class_names, columns=class_names).to_string())

    results["models"]["xgboost_multiclass"] = {
        "n_train_used": int(len(X_train)),
        "n_estimators": args.xgb_estimators,
        "train_seconds": round(mul_time, 1) if mul_time is not None else None,
        "reloaded_from_disk": mul_time is None,
        "per_class": {k: mul_report[k] for k in class_names},
        "macro_avg": mul_report["macro avg"],
        "accuracy": mul_report["accuracy"],
        "confusion_matrix": cm.tolist(),
    }
    if mul_time is not None:
        xgb_mul.save_model(mul_path)
    joblib.dump(attack_encoder, os.path.join(args.out_dir, "netflow_label_encoder.pkl"))
    save_report(results, report_path)
    print(f"\nRapport écrit : {report_path}")
    print(f"Modèles écrits dans : {args.out_dir}")


if __name__ == "__main__":
    main()
