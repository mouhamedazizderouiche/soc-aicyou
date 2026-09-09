"""
train_local_flow_model.py

Entraîne le modèle "flux locaux" : directement sur les flux réels capturés
sur ce réseau (schéma NetFlow v1, flow_feature_extractor.py), et non sur un
jeu public d'un autre environnement. Le décalage de domaine qui a fait
échouer la voie par transfert (NF-CSE-CIC-IDS2018, AUC 0,16 -- voir
journal 06/09) disparaît ici par construction : entraînement et déploiement
partagent le même réseau, la même sonde, la même sémantique de ports.

Deux modèles, cohérents avec les chemins existants du projet :
  - binaire      : bénin / attaque -> alimente le score de risque ;
  - multi-classe : tactique MITRE  -> alimente la correspondance MITRE.

Classes multi-classe et leur tactique MITRE :
  Benign
  Reconnaissance                 (scans)      -> TA0043
  Impact                         (DoS)        -> TA0040
  InitialAccess_CredentialAccess (BruteForce) -> TA0001/TA0006
PrivilegeEscalation est VOLONTAIREMENT hors périmètre : aucune règle ni
aucune vérité terrain locale n'existe pour cette tactique. La forcer
produirait une classe sans exemple réel. On le dit, on ne la fabrique pas.

VALIDATION CROISÉE SANS FUITE -- le point central de ce script
--------------------------------------------------------------
Les flux d'une même campagne d'attaque sont fortement corrélés (même outil,
même minute, mêmes machines). Un découpage k-fold au niveau du flux placerait
des flux de la même campagne des deux côtés d'un pli et gonflerait
artificiellement les scores : le modèle "reconnaîtrait" une campagne déjà vue
plutôt que d'apprendre un comportement. Deux évaluations sont donc produites :

  1. GROUPÉE (StratifiedGroupKFold, groupe = campagne) : c'est la mesure
     honnête. Le modèle est toujours testé sur une campagne qu'il n'a pas
     vue à l'entraînement.
  2. NAÏVE (StratifiedKFold au niveau du flux) : volontairement optimiste,
     fournie UNIQUEMENT pour rendre visible l'écart avec la mesure groupée.
     Cet écart EST la fuite que le groupement supprime.

Limite structurelle assumée : BruteForce ne compte que 2 campagnes et
Reconnaissance 2 également. La validation groupée y revient donc à
entraîner sur une campagne et tester sur l'autre. Les chiffres BruteForce
reposent sur si peu de campagnes indépendantes qu'ils sont indicatifs, pas
concluants -- signalé dans le rapport, pas lissé.

Métriques : précision / rappel / F1 PAR CLASSE. L'exactitude globale n'est
jamais donnée seule (déséquilibre massif : 0,3 % de BruteForce).
"""

import argparse
import collections
import json
import os
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold

from feature_schema import LOCAL_FLOW_FEATURE_COLUMNS, validate_local_flow_schema
from mitre_categories import TACTIC_MITRE_IDS

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "netflow")
RANDOM_STATE = 42

# Vérité terrain locale (Attack) -> nom de tactique MITRE du projet.
ATTACK_TO_TACTIC = {
    "Benign": "Benign",
    "Reconnaissance": "Reconnaissance",
    "DoS": "Impact",
    "BruteForce": "InitialAccess_CredentialAccess",
}
MULTICLASS_ORDER = ["Benign", "Reconnaissance", "Impact", "InitialAccess_CredentialAccess"]


def _sample_weights(y: np.ndarray) -> np.ndarray:
    """
    Poids inversement proportionnels à la fréquence de classe. Sans cela,
    XGBoost optimise l'exactitude en ignorant BruteForce (0,3 %).
    """
    counts = collections.Counter(y.tolist())
    n, k = len(y), len(counts)
    return np.array([n / (k * counts[v]) for v in y], dtype=float)


def _xgb_binary(_num_class=None) -> xgb.XGBClassifier:
    return xgb.XGBClassifier(
        n_estimators=150, max_depth=6, learning_rate=0.1, tree_method="hist",
        n_jobs=4, random_state=RANDOM_STATE, eval_metric="logloss",
    )


def _xgb_multiclass(num_class: int) -> xgb.XGBClassifier:
    return xgb.XGBClassifier(
        n_estimators=150, max_depth=6, learning_rate=0.1, tree_method="hist",
        n_jobs=4, random_state=RANDOM_STATE, objective="multi:softprob",
        num_class=num_class,
    )


def _oof_report(make_model, X, y_names, splits, class_order) -> dict:
    """
    Prédictions hors-pli (out-of-fold) agrégées puis rapport par classe.
    Chaque échantillon est prédit par un modèle qui ne l'a pas vu.

    Ré-encodage LOCAL par pli (indispensable en validation groupée) :
    StratifiedGroupKFold attribue des campagnes entières aux plis et ne
    garantit PAS que chaque classe soit présente dans chaque pli
    d'entraînement -- une tactique dont toutes les campagnes tombent côté
    test laisse le pli d'entraînement sans elle. XGBoost multi-classe exige
    des labels contigus à partir de 0 et refuse un espace troué comme
    [0, 2, 3]. On entraîne donc chaque pli UNIQUEMENT sur les classes qu'il
    contient, ré-encodées 0..m-1, puis on reprojette les prédictions vers
    l'espace global.

    Conséquence assumée, non contournée : une classe absente de
    l'entraînement d'un pli ne peut JAMAIS être prédite pour les
    échantillons de test de ce pli. Son rappel s'en trouve honnêtement
    dégradé dans le rapport agrégé -- ce n'est pas un artefact, c'est la
    réalité d'une classe qu'on ne peut pas apprendre faute de campagne
    indépendante. Les plis concernés sont recensés (absent_from_train_fold)
    pour que le rapport puisse signaler quelles classes ne sont pas
    évaluables de façon robuste.
    """
    labels = {name: i for i, name in enumerate(class_order)}
    y = np.array([labels[v] for v in y_names])
    oof = np.full(len(y), -1, dtype=int)
    absent_counts = collections.Counter()  # classe globale -> nb de plis où absente du train

    for train_idx, test_idx in splits:
        present = sorted(set(y[train_idx].tolist()))          # indices globaux présents
        for missing in set(range(len(class_order))) - set(present):
            absent_counts[class_order[missing]] += 1

        local_of_global = {g: i for i, g in enumerate(present)}
        global_of_local = {i: g for g, i in local_of_global.items()}
        y_train_local = np.array([local_of_global[v] for v in y[train_idx]])

        if len(present) == 1:
            # Un seul classe côté train : aucun classifieur possible, on
            # prédit cette classe. Les échantillons d'autres classes en test
            # seront donc faux -> rappel dégradé, ce qui est correct.
            oof[test_idx] = present[0]
            continue

        model = make_model(len(present))
        model.fit(X.iloc[train_idx], y_train_local,
                  sample_weight=_sample_weights(y_train_local))
        pred_local = model.predict(X.iloc[test_idx])
        oof[test_idx] = np.array([global_of_local[int(p)] for p in pred_local])

    assert (oof >= 0).all(), "des échantillons n'ont jamais été en test"
    rep = classification_report(
        y, oof, labels=list(range(len(class_order))), target_names=class_order,
        digits=4, zero_division=0, output_dict=True,
    )
    n_folds = len(splits)
    return {
        "per_class": {c: {k: rep[c][k] for k in ("precision", "recall", "f1-score", "support")}
                      for c in class_order},
        "macro_avg": {k: rep["macro avg"][k] for k in ("precision", "recall", "f1-score")},
        "accuracy_not_to_be_cited_alone": rep["accuracy"],
        # classes absentes de l'entraînement d'au moins un pli : leur chiffre
        # groupé n'est pas robuste et doit être signalé comme tel.
        "classes_absent_from_some_train_fold": {
            c: absent_counts[c] for c in class_order if absent_counts[c] > 0
        },
        "n_folds": n_folds,
    }


def _print_report(title: str, report: dict) -> None:
    print(f"\n=== {title} ===")
    print(f"{'classe':<32} {'précis.':>9} {'rappel':>9} {'F1':>9} {'support':>9}")
    for c, m in report["per_class"].items():
        print(f"{c:<32} {m['precision']:>9.4f} {m['recall']:>9.4f} "
              f"{m['f1-score']:>9.4f} {int(m['support']):>9d}")
    ma = report["macro_avg"]
    print(f"{'macro avg':<32} {ma['precision']:>9.4f} {ma['recall']:>9.4f} {ma['f1-score']:>9.4f}")
    print(f"(exactitude {report['accuracy_not_to_be_cited_alone']:.4f} — jamais citée seule)")


def main():
    ap = argparse.ArgumentParser(description="Entraîne le modèle flux locaux.")
    ap.add_argument("--csv", default=os.path.join(DATA_DIR, "live_flows_labelled.csv"))
    ap.add_argument("--out-dir", default=DATA_DIR)
    ap.add_argument("--grouped-folds", type=int, default=2,
                    help="k de la validation groupée (borné par la classe la moins "
                         "riche en campagnes ; 2 ici car BruteForce/Reconnaissance "
                         "n'ont que 2 campagnes)")
    ap.add_argument("--naive-folds", type=int, default=5)
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    for needed in ("Attack", "Label", "campaign"):
        if needed not in df.columns:
            raise SystemExit(f"Colonne '{needed}' absente de {args.csv}. "
                             f"Reconstruire avec build_live_flow_dataset.py.")

    X = df[LOCAL_FLOW_FEATURE_COLUMNS].copy()
    validate_local_flow_schema(X, context="train_local_flow_model")
    groups = df["campaign"].to_numpy()
    tactic = df["Attack"].map(ATTACK_TO_TACTIC)
    if tactic.isna().any():
        bad = sorted(df.loc[tactic.isna(), "Attack"].unique())
        raise SystemExit(f"Classe(s) sans tactique définie : {bad}")

    # --- Structure des données (rapportée, pas supposée) --------------
    print("=== Jeu de flux locaux ===")
    dist = df["Attack"].value_counts()
    camp_per_class = df.groupby("Attack")["campaign"].nunique()
    for cls in dist.index:
        print(f"  {cls:<16} {dist[cls]:6d} flux  ({camp_per_class[cls]} campagne(s))")
    print(f"  {'TOTAL':<16} {len(df):6d}")
    min_campaigns = int(camp_per_class.min())
    print(f"\nClasse la moins riche en campagnes : {min_campaigns} "
          f"-> validation groupée bornée à k={min(args.grouped_folds, min_campaigns)}.")

    k_group = min(args.grouped_folds, min_campaigns)
    if k_group < 2:
        raise SystemExit("Moins de 2 campagnes sur une classe : validation groupée "
                         "impossible. Lancer d'autres campagnes (run_attack_campaign.py).")

    # --- Découpages ---------------------------------------------------
    sgkf = StratifiedGroupKFold(n_splits=k_group, shuffle=True, random_state=RANDOM_STATE)
    skf = StratifiedKFold(n_splits=args.naive_folds, shuffle=True, random_state=RANDOM_STATE)

    y_bin = df["Label"].map({0: "Benign", 1: "Attack"}).to_numpy()
    grouped_bin = list(sgkf.split(X, y_bin, groups))
    naive_bin = list(skf.split(X, y_bin))

    y_tac = tactic.to_numpy()
    grouped_tac = list(sgkf.split(X, y_tac, groups))
    naive_tac = list(skf.split(X, y_tac))

    # --- Contrôle anti-fuite : aucune campagne des deux côtés ---------
    for tr, te in grouped_bin:
        assert not (set(groups[tr]) & set(groups[te])), "FUITE : campagne partagée"
    print("Contrôle anti-fuite groupé : aucune campagne partagée entre train et test. OK")

    reports = {
        "binary_grouped": _oof_report(_xgb_binary, X, y_bin, grouped_bin, ["Benign", "Attack"]),
        "binary_naive": _oof_report(_xgb_binary, X, y_bin, naive_bin, ["Benign", "Attack"]),
        "multiclass_grouped": _oof_report(
            _xgb_multiclass, X, y_tac, grouped_tac, MULTICLASS_ORDER),
        "multiclass_naive": _oof_report(
            _xgb_multiclass, X, y_tac, naive_tac, MULTICLASS_ORDER),
    }

    _print_report(f"BINAIRE — validation GROUPÉE (k={k_group}, sans fuite) [MESURE HONNÊTE]",
                  reports["binary_grouped"])
    _print_report(f"BINAIRE — validation naïve (k={args.naive_folds}, fuite) [contraste]",
                  reports["binary_naive"])
    _print_report(f"MULTI-CLASSE — validation GROUPÉE (k={k_group}, sans fuite) [MESURE HONNÊTE]",
                  reports["multiclass_grouped"])
    _print_report(f"MULTI-CLASSE — validation naïve (k={args.naive_folds}, fuite) [contraste]",
                  reports["multiclass_naive"])

    # --- Comparaison groupée vs naïve + évaluabilité par classe -------
    # Une classe n'est PAS évaluable de façon robuste en groupé si elle a
    # moins de 3 campagnes indépendantes (train/test ne peut alors reposer
    # que sur 1 campagne de chaque côté au mieux) OU si elle a manqué de
    # l'entraînement d'au moins un pli. Seuil à 3 : en dessous, un chiffre
    # groupé repose sur une seule campagne de test et n'est pas concluant.
    MIN_CAMPAIGNS_ROBUST = 3
    grouped_mc = reports["multiclass_grouped"]
    naive_mc = reports["multiclass_naive"]
    absent = grouped_mc.get("classes_absent_from_some_train_fold", {})
    tactic_to_attack = {v: k for k, v in ATTACK_TO_TACTIC.items()}
    comparison = {}
    print("\n=== MULTI-CLASSE — groupée vs naïve, par classe ===")
    print(f"{'classe':<32} {'F1 group.':>10} {'F1 naïve':>10} {'écart':>8} {'robuste?':>10}")
    for c in MULTICLASS_ORDER:
        f1_g = grouped_mc["per_class"][c]["f1-score"]
        f1_n = naive_mc["per_class"][c]["f1-score"]
        n_camp = int(camp_per_class.get(tactic_to_attack[c], 0))
        robust = (n_camp >= MIN_CAMPAIGNS_ROBUST) and (c not in absent)
        comparison[c] = {
            "f1_grouped": f1_g, "f1_naive": f1_n, "gap_naive_minus_grouped": f1_n - f1_g,
            "n_campaigns": n_camp, "absent_from_some_train_fold": absent.get(c, 0),
            "grouped_robustly_evaluable": robust,
        }
        flag = "oui" if robust else "NON"
        print(f"{c:<32} {f1_g:>10.4f} {f1_n:>10.4f} {f1_n - f1_g:>+8.4f} {flag:>10}")

    not_robust = [c for c, v in comparison.items() if not v["grouped_robustly_evaluable"]]
    if not_robust:
        print("\nClasses NON évaluables de façon robuste en groupé (trop peu de "
              "campagnes indépendantes ou absentes d'un pli d'entraînement) :")
        for c in not_robust:
            v = comparison[c]
            reason = []
            if v["n_campaigns"] < MIN_CAMPAIGNS_ROBUST:
                reason.append(f"{v['n_campaigns']} campagne(s)")
            if v["absent_from_some_train_fold"]:
                reason.append(f"absente de {v['absent_from_some_train_fold']} pli(s) d'entraînement")
            print(f"  - {c} : {', '.join(reason)}. Ne pas publier son F1 groupé comme fiable.")

    # --- Modèles finaux : entraînés sur TOUTES les données ------------
    binary_model = _xgb_binary()
    binary_model.fit(X, (df["Label"] == 1).astype(int),
                     sample_weight=_sample_weights(df["Label"].to_numpy()))
    binary_model.save_model(os.path.join(args.out_dir, "netflow_local_xgboost_binary.json"))

    tac_labels = {name: i for i, name in enumerate(MULTICLASS_ORDER)}
    y_tac_idx = np.array([tac_labels[v] for v in y_tac])
    multiclass_model = _xgb_multiclass(len(MULTICLASS_ORDER))
    multiclass_model.fit(X, y_tac_idx, sample_weight=_sample_weights(y_tac_idx))
    multiclass_model.save_model(os.path.join(args.out_dir, "netflow_local_xgboost_multiclass.json"))
    joblib.dump(MULTICLASS_ORDER, os.path.join(args.out_dir, "netflow_local_classes.pkl"))

    # --- Rapport horodaté (format validation_report.json) -------------
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": "local_flow_netflow_v1",
        "features": LOCAL_FLOW_FEATURE_COLUMNS,
        "n_flows": int(len(df)),
        "class_distribution": {k: int(v) for k, v in dist.items()},
        "campaigns_per_class": {k: int(v) for k, v in camp_per_class.items()},
        "multiclass_classes": MULTICLASS_ORDER,
        "tactic_mitre_ids": {t: TACTIC_MITRE_IDS.get(t, "N/A") for t in MULTICLASS_ORDER
                             if t != "Benign"},
        "privilege_escalation": "hors périmètre : aucune règle ni vérité terrain locale",
        "cross_validation": {
            "grouped": {
                "method": "StratifiedGroupKFold", "k": k_group, "group": "campaign",
                "leakage_safe": True,
                "note": "mesure honnête : test toujours sur une campagne non vue",
            },
            "naive": {
                "method": "StratifiedKFold", "k": args.naive_folds, "group": None,
                "leakage_safe": False,
                "note": "optimiste, fournie pour rendre visible l'écart = la fuite supprimée",
            },
        },
        "min_campaigns_any_class": min_campaigns,
        "caveat_bruteforce": (
            "BruteForce ne compte que 2 campagnes : la validation groupée y revient "
            "à entraîner sur une campagne et tester sur l'autre. Chiffres indicatifs, "
            "non concluants."
        ),
        "multiclass_grouped_vs_naive": comparison,
        "min_campaigns_for_robust_grouped": MIN_CAMPAIGNS_ROBUST,
        "classes_not_robustly_evaluable_grouped": not_robust,
        "metrics": reports,
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = os.path.join(args.out_dir, f"local_flow_validation_report_{stamp}.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    # copie stable pour les consommateurs (dashboard, docs)
    with open(os.path.join(args.out_dir, "local_flow_validation_report.json"), "w",
              encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\nRapport écrit : {out}")
    print("Modèles écrits : netflow_local_xgboost_binary.json, "
          "netflow_local_xgboost_multiclass.json, netflow_local_classes.pkl")


if __name__ == "__main__":
    main()
