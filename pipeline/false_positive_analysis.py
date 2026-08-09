"""
false_positive_analysis.py

Root-cause analysis of the model's false positives: normal traffic
classified as attack. Compares feature distributions between false
positives and true negatives to understand WHY the model is fooled.
"""

import pandas as pd
from analysis_engine import AnalysisEngine
from preprocess import preprocess

X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
    "data/nsl-kdd/KDDTrain+.txt",
    "data/nsl-kdd/KDDTest+.txt",
)

engine = AnalysisEngine()
results = engine.analyze(X_test, true_labels=test_labels)

# False positives: true label is normal, but model flagged as attack
fp_mask = (y_test == 0) & (results["is_attack"] == 1)
tn_mask = (y_test == 0) & (results["is_attack"] == 0)

fp_indices = X_test[fp_mask].index
tn_indices = X_test[tn_mask].index

print(f"False positives: {fp_mask.sum()}")
print(f"True negatives (correct): {tn_mask.sum()}\n")

# Compare feature distributions: what's different about the FPs?
fp_features = X_test.loc[fp_indices]
tn_features = X_test.loc[tn_indices]

comparison = pd.DataFrame({
    "false_positive_mean": fp_features.mean(),
    "true_negative_mean": tn_features.mean(),
})
comparison["abs_diff"] = (comparison["false_positive_mean"] - comparison["true_negative_mean"]).abs()
comparison = comparison.sort_values("abs_diff", ascending=False)

print("=== Top 10 features most different between False Positives and True Negatives ===\n")
print(comparison.head(10).to_string())

# Show the risk scores of the false positives - are they borderline or extreme?
fp_scores = results.loc[fp_indices, "risk_score"]
print(f"\n=== Risk score distribution among false positives ===")
print(fp_scores.describe())

# Cross-reference with predicted tactic - what did the model THINK it saw?
print(f"\n=== What tactic did the model assign to these false positives? ===")
print(results.loc[fp_indices, "predicted_tactic"].value_counts())
