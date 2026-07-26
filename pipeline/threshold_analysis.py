"""
threshold_analysis.py

Analyse du compromis precision/recall selon différents seuils de décision,
pour choisir un seuil adapté à un contexte SOC (priorité au recall).
"""

import numpy as np
import xgboost as xgb
from sklearn.metrics import precision_score, recall_score, f1_score

from preprocess import preprocess

X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
    "data/nsl-kdd/KDDTrain+.txt",
    "data/nsl-kdd/KDDTest+.txt",
)

model = xgb.XGBClassifier()
model.load_model("data/xgboost_baseline.json")

y_proba = model.predict_proba(X_test)[:, 1]

print(f"{'Seuil':>6} | {'Precision':>10} | {'Recall':>8} | {'F1':>6} | {'Faux négatifs':>14}")
print("-" * 60)

thresholds = np.arange(0.1, 1.0, 0.1)
results = []

for t in thresholds:
    y_pred = (y_proba >= t).astype(int)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    false_negatives = ((y_test == 1) & (y_pred == 0)).sum()

    results.append((t, precision, recall, f1, false_negatives))
    print(f"{t:>6.1f} | {precision:>10.4f} | {recall:>8.4f} | {f1:>6.4f} | {false_negatives:>14}")

# Seuil optimal selon F1 (compromis équilibré)
best_f1 = max(results, key=lambda r: r[3])
print(f"\nMeilleur seuil (F1-score) : {best_f1[0]:.1f} -> F1={best_f1[3]:.4f}")

# Seuil orienté sécurité : recall >= 0.90 minimum, avec la meilleure precision possible
security_candidates = [r for r in results if r[2] >= 0.90]
if security_candidates:
    best_security = max(security_candidates, key=lambda r: r[1])
    print(f"Meilleur seuil (recall >= 0.90, orienté sécurité) : "
          f"{best_security[0]:.1f} -> recall={best_security[2]:.4f}, precision={best_security[1]:.4f}")
else:
    print("Aucun seuil testé n'atteint un recall >= 0.90 — affiner la granularité.")
