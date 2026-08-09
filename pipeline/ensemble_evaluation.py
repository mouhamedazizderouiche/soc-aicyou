"""
ensemble_evaluation.py

Combines XGBoost (supervised) + Isolation Forest (unsupervised) via
OR logic: flag as attack if either model flags it. Tests whether the
combined system meaningfully improves recall without unacceptable
false positive cost.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

from preprocess import preprocess
from analysis_engine import AnalysisEngine

X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
    "data/nsl-kdd/KDDTrain+.txt",
    "data/nsl-kdd/KDDTest+.txt",
)

X_train_normal = X_train[y_train == 0]
iso_forest = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
iso_forest.fit(X_train_normal)
iso_pred = (iso_forest.predict(X_test) == -1).astype(int)

engine = AnalysisEngine()
xgb_results = engine.analyze(X_test)
xgb_pred = xgb_results["is_attack"].values

# Ensemble: OR logic (either model flags -> attack)
ensemble_pred = ((xgb_pred == 1) | (iso_pred == 1)).astype(int)

print("=== XGBoost alone ===")
print(classification_report(y_test, xgb_pred, target_names=["normal", "attack"]))

print("=== Isolation Forest alone ===")
print(classification_report(y_test, iso_pred, target_names=["normal", "attack"]))

print("=== Ensemble (XGBoost OR Isolation Forest) ===")
print(classification_report(y_test, ensemble_pred, target_names=["normal", "attack"]))

cm = confusion_matrix(y_test, ensemble_pred)
print("Confusion matrix (ensemble):")
print(cm)

tn, fp, fn, tp = cm.ravel()
print(f"\nEnsemble recall  : {tp/(tp+fn):.2%}")
print(f"Ensemble FPR     : {fp/(fp+tn):.2%}")
print(f"XGBoost alone recall was  : 70.05%  (baseline)")
print(f"Recall improvement       : +{(tp/(tp+fn) - 0.7005)*100:.1f} points")
