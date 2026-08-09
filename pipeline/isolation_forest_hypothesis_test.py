"""
isolation_forest_hypothesis_test.py

Hypothesis: XGBoost's recall ceiling is caused by attack types absent
from training (a structural limit of supervised learning). An
unsupervised anomaly detector (Isolation Forest), trained ONLY on
normal traffic, should not have this limitation - it doesn't need to
have seen an attack type before to flag it as anomalous.

Test: does Isolation Forest catch attacks that XGBoost misses,
specifically the "novel" attack types never seen in training?
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

from preprocess import preprocess
from analysis_engine import AnalysisEngine

X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
    "data/nsl-kdd/KDDTrain+.txt",
    "data/nsl-kdd/KDDTest+.txt",
)

# --- Identify which attack types in test are "novel" (absent from train) ---
train_attack_types = set(train_labels[train_labels != "normal"].unique())
test_attack_types = set(test_labels[test_labels != "normal"].unique())
novel_types = test_attack_types - train_attack_types
print(f"Attack types NEVER seen in training ({len(novel_types)}): {sorted(novel_types)}\n")

# --- Train Isolation Forest on NORMAL traffic only (correct unsupervised setup) ---
X_train_normal = X_train[y_train == 0]
print(f"Training Isolation Forest on {len(X_train_normal)} normal-only samples...")

iso_forest = IsolationForest(
    n_estimators=200,
    contamination=0.05,  # expected proportion of anomalies, tuned conservatively
    random_state=42,
    n_jobs=-1,
)
iso_forest.fit(X_train_normal)

# IsolationForest.predict: -1 = anomaly (flag as attack), 1 = normal
iso_pred_raw = iso_forest.predict(X_test)
iso_pred = (iso_pred_raw == -1).astype(int)

print("\n=== Isolation Forest — overall performance ===")
print(classification_report(y_test, iso_pred, target_names=["normal", "attack"]))

# --- Compare: on NOVEL attack types specifically, who catches more? ---
engine = AnalysisEngine()
xgb_results = engine.analyze(X_test)
xgb_pred = xgb_results["is_attack"].values

novel_mask = test_labels.isin(novel_types)
print(f"\n=== Head-to-head on NOVEL attack types only ({novel_mask.sum()} samples) ===\n")

xgb_recall_novel = xgb_pred[novel_mask.values].mean()
iso_recall_novel = iso_pred[novel_mask.values].mean()

print(f"XGBoost recall on novel attack types  : {xgb_recall_novel:.2%}")
print(f"Isolation Forest recall on novel types : {iso_recall_novel:.2%}")

# --- The real question: does Isolation Forest catch things XGBoost misses? ---
xgb_missed = (y_test.values == 1) & (xgb_pred == 0)
iso_catches_xgb_misses = xgb_missed & (iso_pred == 1)

print(f"\nAttacks XGBoost missed entirely       : {xgb_missed.sum()}")
print(f"...of those, Isolation Forest caught  : {iso_catches_xgb_misses.sum()} "
      f"({iso_catches_xgb_misses.sum() / xgb_missed.sum():.1%})")

# Breakdown by attack type of what Isolation Forest recovers
recovered_labels = test_labels[iso_catches_xgb_misses]
print(f"\n=== Attack types Isolation Forest recovers (that XGBoost missed) ===")
print(recovered_labels.value_counts())

# --- Cost check: does Isolation Forest bring unacceptable false positives? ---
iso_fp = ((y_test.values == 0) & (iso_pred == 1)).sum()
xgb_fp = ((y_test.values == 0) & (xgb_pred == 0)).sum()  # placeholder fix below
xgb_fp = ((y_test.values == 0) & (xgb_pred == 1)).sum()
print(f"\n=== False positive comparison ===")
print(f"XGBoost false positives           : {xgb_fp} ({xgb_fp/(y_test==0).sum():.2%})")
print(f"Isolation Forest false positives  : {iso_fp} ({iso_fp/(y_test==0).sum():.2%})")
