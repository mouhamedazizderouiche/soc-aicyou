"""
train_isolation_forest.py

Trains and persists the Isolation Forest anomaly detector, used as
the unsupervised complement to the XGBoost supervised classifier
(see isolation_forest_hypothesis_test.py for the validation that
motivated this addition).

Trained EXCLUSIVELY on normal traffic - correct unsupervised setup,
the model learns what "normal" looks like and flags deviations,
rather than learning attack signatures directly.
"""

import joblib
from sklearn.ensemble import IsolationForest

from preprocess import preprocess

X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
    "data/nsl-kdd/KDDTrain+.txt",
    "data/nsl-kdd/KDDTest+.txt",
)

X_train_normal = X_train[y_train == 0]
print(f"Training on {len(X_train_normal)} normal-only samples...")

iso_forest = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42,
    n_jobs=-1,
)
iso_forest.fit(X_train_normal)

joblib.dump(iso_forest, "data/isolation_forest.pkl")
print("Saved to data/isolation_forest.pkl")
