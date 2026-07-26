"""
train_model.py

Entraînement d'un premier modèle XGBoost baseline sur NSL-KDD.
Utilise predict_proba() pour obtenir un score de risque continu (0-1),
plutôt qu'une simple prédiction binaire.
"""

import xgboost as xgb
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    confusion_matrix,
)

from preprocess import preprocess

X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
    "data/nsl-kdd/KDDTrain+.txt",
    "data/nsl-kdd/KDDTest+.txt",
)

# Vérification du déséquilibre de classes pour scale_pos_weight
neg, pos = y_train.value_counts()[0], y_train.value_counts()[1]
scale_pos_weight = neg / pos
print(f"scale_pos_weight calculé : {scale_pos_weight:.3f}\n")

model = xgb.XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    scale_pos_weight=scale_pos_weight,
    eval_metric="logloss",
    random_state=42,
)

print("Entraînement en cours...")
model.fit(X_train, y_train)
print("Entraînement terminé.\n")

# predict_proba() : score de risque continu, PAS predict() binaire.
# C'est ce score qui alimentera le module de priorisation (Phase 4-5).
y_proba = model.predict_proba(X_test)[:, 1]
y_pred = (y_proba >= 0.5).astype(int)  # seuil par défaut, ajustable plus tard

print("=== Rapport de classification ===")
print(classification_report(y_test, y_pred, target_names=["normal", "attack"]))

print(f"AUC-ROC : {roc_auc_score(y_test, y_proba):.4f}")

print("\n=== Matrice de confusion ===")
print(confusion_matrix(y_test, y_pred))

print("\n=== Exemple de scores de risque (10 premiers échantillons test) ===")
for i in range(10):
    print(f"Vrai label: {test_labels.iloc[i]:15s} | "
          f"Score de risque: {y_proba[i]:.4f} | "
          f"Prédiction: {'attack' if y_pred[i] else 'normal'}")

model.save_model("data/xgboost_baseline.json")
print("\nModèle sauvegardé dans data/xgboost_baseline.json")
