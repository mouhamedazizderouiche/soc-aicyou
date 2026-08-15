"""
tactic_classifier_smote_v2.py

Version affinée : SMOTE avec ratio de rééquilibrage modéré plutôt
qu'un équilibrage total, pour éviter la sur-amplification des
classes extrêmement rares (leçon tirée de la v1 : x883 sur
PrivilegeEscalation dégradait la precision).
"""

import xgboost as xgb
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE

from preprocess import preprocess
from mitre_categories import label_to_tactic
from tactic_classifier import build_tactic_dataset

X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
    "data/nsl-kdd/KDDTrain+.txt",
    "data/nsl-kdd/KDDTest+.txt",
)

X_train_tactic, y_train_tactic_raw = build_tactic_dataset(X_train, train_labels)
X_test_tactic, y_test_tactic_raw = build_tactic_dataset(X_test, test_labels)

tactic_encoder = LabelEncoder()
y_train_tactic = tactic_encoder.fit_transform(y_train_tactic_raw)

known_classes = set(tactic_encoder.classes_)
mask_known = y_test_tactic_raw.isin(known_classes)
X_test_tactic = X_test_tactic[mask_known]
y_test_tactic = tactic_encoder.transform(y_test_tactic_raw[mask_known])

# Ratio modéré : on cible un maximum de 3000 exemples pour les classes
# minoritaires, pas un équilibrage total avec la classe majoritaire (45927).
# PrivilegeEscalation (idx à déterminer dynamiquement) : x57 au lieu de x883.
class_indices = {name: i for i, name in enumerate(tactic_encoder.classes_)}
sampling_strategy = {
    class_indices["PrivilegeEscalation"]: 3000,
    class_indices["InitialAccess_CredentialAccess"]: 15000,
}

print("Distribution AVANT SMOTE (train) :")
print(pd.Series(y_train_tactic).value_counts())

smote = SMOTE(random_state=42, k_neighbors=4, sampling_strategy=sampling_strategy)
X_train_resampled, y_train_resampled = smote.fit_resample(X_train_tactic, y_train_tactic)

print("\nDistribution APRÈS SMOTE modéré (train) :")
print(pd.Series(y_train_resampled).value_counts())

model = xgb.XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    objective="multi:softprob",
    num_class=len(tactic_encoder.classes_),
    eval_metric="mlogloss",
    random_state=42,
)

print("\nEntraînement...")
model.fit(X_train_resampled, y_train_resampled)
print("Terminé.\n")

y_pred = model.predict(X_test_tactic)

print("=== Rapport de classification (SMOTE modéré) ===")
print(classification_report(
    y_test_tactic, y_pred,
    target_names=tactic_encoder.classes_,
    zero_division=0,
))

print("=== Matrice de confusion ===")
print(pd.DataFrame(
    confusion_matrix(y_test_tactic, y_pred),
    index=tactic_encoder.classes_,
    columns=tactic_encoder.classes_,
))

model.save_model("data/xgboost_tactic_classifier_final.json")

import joblib
joblib.dump(tactic_encoder, "data/tactic_label_encoder.pkl")

print("\nModèle final sauvegardé.")
# =========================================================
# Sauvegarde des métriques (pour affichage dashboard, évite le
# hardcoding de F1-scores qui se périment silencieusement --
# voir découverte du 14/08/2026 : les scores affichés dans
# dashboard.py étaient figés dans le code source, déconnectés
# de toute ré-évaluation réelle du modèle).
# =========================================================
import json
from datetime import datetime, timezone

report_dict = classification_report(
    y_test_tactic, y_pred,
    target_names=tactic_encoder.classes_,
    output_dict=True,
    zero_division=0,
)

tactic_metrics = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "training_method": "XGBoost + SMOTE modere (voir sampling_strategy ci-dessus)",
    "attack_type_coverage": {
        "total_types_mapped": len(__import__("mitre_categories").TACTIC_GROUPS),
        "note": (
            "Couverture etendue le 14/08/2026 de 22 a 39 types d'attaque NSL-KDD "
            "(les 17 types absents du train set, ~29% des echantillons d'attaque "
            "du test set, etaient auparavant exclus de toute evaluation -- voir "
            "docs/journal-technique.md)."
        ),
    },
    "overall_accuracy": round(report_dict["accuracy"], 4),
    "per_tactic": {
        tactic: {
            "precision": round(report_dict[tactic]["precision"], 4),
            "recall": round(report_dict[tactic]["recall"], 4),
            "f1_score": round(report_dict[tactic]["f1-score"], 4),
            "support": int(report_dict[tactic]["support"]),
        }
        for tactic in tactic_encoder.classes_
    },
    "known_limitations": {
        "PrivilegeEscalation": (
            "F1 le plus faible des 4 tactiques -- seulement 52 exemples reels "
            "en entrainement. La precision reste faible meme apres SMOTE modere "
            "(amplification x57, 3000 exemples synthetiques). Traiter toute "
            "alerte de cette categorie en priorite manuelle systematique, "
            "independamment du score de confiance affiche."
        ),
    },
}

with open("data/tactic_classifier_report.json", "w") as f:
    json.dump(tactic_metrics, f, indent=2)

print("Métriques sauvegardées dans data/tactic_classifier_report.json")
