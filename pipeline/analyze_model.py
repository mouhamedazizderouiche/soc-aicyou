"""
analyze_model.py

Analyse l'importance des features du modèle XGBoost entraîné,
pour comprendre sur quels signaux il base ses décisions.
"""

import xgboost as xgb
import pandas as pd

from preprocess import preprocess

X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
    "data/nsl-kdd/KDDTrain+.txt",
    "data/nsl-kdd/KDDTest+.txt",
)

model = xgb.XGBClassifier()
model.load_model("data/xgboost_baseline.json")

importance = model.feature_importances_
feature_names = X_train.columns

importance_df = pd.DataFrame({
    "feature": feature_names,
    "importance": importance,
}).sort_values("importance", ascending=False)

print("=== Top 15 features les plus importantes ===\n")
print(importance_df.head(15).to_string(index=False))

importance_df.to_csv("data/feature_importance.csv", index=False)
print("\nSauvegardé dans data/feature_importance.csv")
