"""
netflow_transfer_test.py

PORTE DE DÉCISION du chantier NetFlow.

Applique les modèles entraînés sur NF-CSE-CIC-IDS2018 (banc d'essai CIC,
2018) au trafic réel capturé sur cette VM (2026), étiqueté par
netflow_ground_truth. Les deux jeux partagent EXACTEMENT le même schéma
de 12 features : aucune couche d'adaptation n'intervient, ce qui est
précisément ce qui rend la mesure interprétable. Ce qui est mesuré ici
est donc le transfert inter-domaine seul.

CRITÈRE DE POURSUITE, FIXÉ AVANT LA MESURE
------------------------------------------
Rappel > 50% sur les classes scan et DoS avec le modèle binaire.
  - atteint      -> intégrer (étape 2)
  - non atteint  -> ARRÊTER, consigner l'échec de généralisation comme
                    constat de recherche, conserver le cadrage NSL-KDD.
Le critère porte sur le modèle BINAIRE : c'est lui qui décide
« attaque / pas attaque », donc lui qui conditionne toute la suite.

DEUX NIVEAUX D'ÉTIQUETTES — PIÈGE VÉRIFIÉ
------------------------------------------
La colonne `Attack` de NF-CSE-CIC-IDS2018 contient 15 classes FINES
(« DoS attacks-Hulk », « SSH-Bruteforce »...), pas les 7 catégories
parentes décrites sur la page de publication. Le modèle multi-classe
prédit donc des classes fines. Les comparer directement à la vérité
terrain locale, exprimée en catégories, donnerait 0% par simple
non-correspondance de chaînes — ce qui se lirait à tort comme un échec
de transfert. Toute prédiction est donc ramenée à sa catégorie parente
via netflow_ground_truth.to_parent_category(), dont la correspondance a
été vérifiée par sommation contre les effectifs publiés (six sommes
exactes).

ASYMÉTRIE DE CLASSES — À LIRE AVANT D'INTERPRÉTER LE MULTI-CLASSE
------------------------------------------------------------------
NF-CSE-CIC-IDS2018 ne contient AUCUNE classe de reconnaissance ou de
scan de ports (ses sept classes : Benign, BruteForce, Bot, DoS, DDoS,
Infiltration, Web Attacks). Or 88% des flux d'attaque réels capturés ici
sont des scans nmap. Le modèle multi-classe ne peut donc pas prédire
correctement ces flux : la bonne réponse n'existe pas dans son
vocabulaire. Ce n'est pas une contre-performance du modèle, c'est une
limite du jeu d'entraînement.

Conséquence sur la lecture des résultats :
  - binaire      : évaluable sur toutes les classes.
  - multi-classe : évaluable UNIQUEMENT sur DoS et BruteForce, présentes
                   dans les deux domaines. Pour la reconnaissance, on
                   rapporte ce que le modèle prédit, sans le compter
                   comme erreur ni comme succès.
Une seule souplesse est admise et signalée : notre flood mono-source est
compté correct s'il est prédit DoS OU DDoS, ces deux classes ne se
distinguant que par le nombre de sources — information absente d'un flux
NetFlow isolé.
"""

import argparse
import json
import logging
import os

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

from flow_feature_extractor import NETFLOW_V1_MODEL_COLUMNS, validate_netflow_v1_schema
from netflow_ground_truth import to_parent_category

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("netflow_transfer_test")

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "netflow")

# Classes du jeu d'entraînement acceptées comme prédiction correcte pour
# chaque classe de vérité terrain locale. Une classe locale absente de ce
# tableau n'a pas d'équivalent dans le domaine source.
ACCEPTABLE_PREDICTIONS = {
    "DoS": {"DoS", "DDoS"},
    "BruteForce": {"BruteForce"},
    "Benign": {"Benign"},
}
CLASSES_WITHOUT_SOURCE_EQUIVALENT = {"Reconnaissance"}

GATE_MIN_RECALL = 0.50
GATE_CLASSES = ("Reconnaissance", "DoS")


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "f1": f1,
            "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0}


def main():
    parser = argparse.ArgumentParser(description="Test de transfert inter-domaine NetFlow.")
    parser.add_argument("--live", default=os.path.join(DATA_DIR, "live_flows_labelled.csv"))
    parser.add_argument("--model-dir", default=DATA_DIR)
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="seuil de décision du modèle binaire")
    parser.add_argument("--out", default=os.path.join(DATA_DIR, "netflow_transfer_report.json"))
    args = parser.parse_args()

    live = pd.read_csv(args.live)
    X = live[NETFLOW_V1_MODEL_COLUMNS]
    validate_netflow_v1_schema(X, context="netflow_transfer_test", model_input=True)

    y_bin = live["Label"].to_numpy()
    truth = live["Attack"].to_numpy()

    print("=== Jeu de trafic réel ===")
    for cls, n in live["Attack"].value_counts().items():
        print(f"  {cls:<16} {n:6d}  ({n / len(live):.1%})")
    print(f"  {'TOTAL':<16} {len(live):6d}")

    binary_model = xgb.XGBClassifier()
    binary_model.load_model(os.path.join(args.model_dir, "netflow_xgboost_binary.json"))
    proba = binary_model.predict_proba(X)[:, 1]
    pred_bin = (proba >= args.threshold).astype(int)

    overall = binary_metrics(y_bin, pred_bin)
    print(f"\n=== Modèle binaire — seuil {args.threshold} ===")
    print(f"  Rappel sur les attaques  : {overall['recall']:.4f} "
          f"({overall['tp']}/{overall['tp'] + overall['fn']})")
    print(f"  Précision                : {overall['precision']:.4f}")
    print(f"  Taux de faux positifs    : {overall['false_positive_rate']:.4f} "
          f"({overall['fp']}/{overall['fp'] + overall['tn']} flux bénins alertés)")

    print(f"\n  Rappel par classe de vérité terrain :")
    per_class = {}
    for cls in sorted(set(truth)):
        mask = truth == cls
        if cls == "Benign":
            rate = float((pred_bin[mask] == 0).mean())
            per_class[cls] = {"n": int(mask.sum()), "correct_rate": rate,
                              "metric": "taux de bénins correctement non alertés"}
            print(f"    {cls:<16} n={int(mask.sum()):6d}  "
                  f"non alertés : {rate:.4f}")
        else:
            rate = float((pred_bin[mask] == 1).mean())
            per_class[cls] = {"n": int(mask.sum()), "recall": rate,
                              "metric": "rappel"}
            print(f"    {cls:<16} n={int(mask.sum()):6d}  "
                  f"rappel      : {rate:.4f}  "
                  f"({int((pred_bin[mask] == 1).sum())} détectés)")

    print(f"\n  Score moyen attribué par classe (probabilité d'attaque) :")
    for cls in sorted(set(truth)):
        mask = truth == cls
        print(f"    {cls:<16} moyenne={proba[mask].mean():.4f}  "
              f"médiane={np.median(proba[mask]):.4f}")

    # ---------------- Multi-classe ------------------------------------
    multi_model = xgb.XGBClassifier()
    multi_model.load_model(os.path.join(args.model_dir, "netflow_xgboost_multiclass.json"))
    encoder = joblib.load(os.path.join(args.model_dir, "netflow_label_encoder.pkl"))
    pred_fine = encoder.inverse_transform(multi_model.predict(X))
    # Ramené aux catégories parentes : c'est le seul niveau comparable à
    # la vérité terrain locale (voir en-tête, « deux niveaux d'étiquettes »).
    pred_multi = np.array([to_parent_category(label) for label in pred_fine])

    print(f"\n=== Modèle multi-classe ===")
    print("  Répartition des prédictions par classe réelle "
          "(lignes = vérité terrain locale) :")
    crosstab = pd.crosstab(pd.Series(truth, name="réel"),
                            pd.Series(pred_multi, name="prédit (catégorie)"))
    print(crosstab.to_string())

    print("\n  Détail des classes fines effectivement prédites :")
    fine_crosstab = pd.crosstab(pd.Series(truth, name="réel"),
                                 pd.Series(pred_fine, name="prédit (classe fine)"))
    print(fine_crosstab.to_string())

    multi_scores = {}
    print("\n  Lecture :")
    for cls in sorted(set(truth)):
        mask = truth == cls
        if cls in CLASSES_WITHOUT_SOURCE_EQUIVALENT:
            top = pd.Series(pred_multi[mask]).value_counts().head(3)
            print(f"    {cls:<16} AUCUN équivalent dans le jeu source — "
                  f"non évaluable. Prédictions majoritaires : "
                  f"{dict(top)}")
            multi_scores[cls] = {"evaluable": False,
                                 "top_predictions": {k: int(v) for k, v in top.items()}}
            continue
        acceptable = ACCEPTABLE_PREDICTIONS.get(cls, {cls})
        correct = float(np.isin(pred_multi[mask], list(acceptable)).mean())
        relaxed = " (DoS ou DDoS acceptés)" if cls == "DoS" else ""
        print(f"    {cls:<16} exactitude : {correct:.4f}{relaxed}")
        multi_scores[cls] = {"evaluable": True, "accuracy": correct,
                             "acceptable_as_correct": sorted(acceptable)}

    # ---------------- Verdict de la porte ------------------------------
    print(f"\n=== PORTE DE DÉCISION ===")
    print(f"Critère fixé avant mesure : rappel binaire > {GATE_MIN_RECALL:.0%} "
          f"sur {' et '.join(GATE_CLASSES)}.")
    verdict = True
    for cls in GATE_CLASSES:
        if cls not in per_class:
            print(f"  {cls:<16} ABSENT du jeu réel — critère non vérifiable.")
            verdict = False
            continue
        recall = per_class[cls].get("recall", 0.0)
        passed = recall > GATE_MIN_RECALL
        verdict = verdict and passed
        print(f"  {cls:<16} rappel {recall:.4f}  -> {'PASSE' if passed else 'ÉCHOUE'}")

    print(f"\nVERDICT : {'POURSUIVRE vers l intégration' if verdict else 'ARRÊTER — consigner comme constat de recherche'}")

    report = {
        "live_dataset": os.path.basename(args.live),
        "n_live_flows": int(len(live)),
        "live_class_distribution": {k: int(v) for k, v in live["Attack"].value_counts().items()},
        "binary_threshold": args.threshold,
        "binary_overall": overall,
        "binary_per_class": per_class,
        "mean_attack_probability_per_class": {
            cls: float(proba[truth == cls].mean()) for cls in sorted(set(truth))
        },
        "multiclass_crosstab_parent": crosstab.to_dict(),
        "multiclass_crosstab_fine": fine_crosstab.to_dict(),
        "multiclass_per_class": multi_scores,
        "gate": {"criterion_recall": GATE_MIN_RECALL,
                 "classes": list(GATE_CLASSES),
                 "passed": bool(verdict)},
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\nRapport écrit : {args.out}")

    raise SystemExit(0 if verdict else 2)


if __name__ == "__main__":
    main()
