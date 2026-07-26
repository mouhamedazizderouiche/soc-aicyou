"""
preprocess.py

Prétraitement du dataset NSL-KDD pour l'entraînement :
- Encodage des variables catégorielles
- Binarisation du label (normal=0, attack=1)
- Séparation features / target
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

from explore_dataset import load_nsl_kdd, COLUMN_NAMES

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]


def preprocess(train_path: str, test_path: str):
    train_df = load_nsl_kdd(train_path)
    test_df = load_nsl_kdd(test_path)

    train_df = train_df.drop(columns=["difficulty_level"])
    test_df = test_df.drop(columns=["difficulty_level"])

    train_df["target"] = (train_df["label"] != "normal").astype(int)
    test_df["target"] = (test_df["label"] != "normal").astype(int)

    train_labels = train_df["label"]
    test_labels = test_df["label"]

    train_df = train_df.drop(columns=["label"])
    test_df = test_df.drop(columns=["label"])

    # Encodage des variables catégorielles. On fit UNIQUEMENT sur train,
    # puis on applique sur test — sinon on aurait une fuite de données
    # (data leakage) entre les deux ensembles.
    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        train_df[col] = le.fit_transform(train_df[col])

        # Ajouter "unknown" comme classe supplémentaire pour gérer les
        # catégories vues dans test mais absentes de train.
        le.classes_ = np.append(le.classes_, "unknown")

        test_df[col] = test_df[col].apply(
            lambda x: x if x in le.classes_ else "unknown"
        )
        test_df[col] = le.transform(test_df[col])
        encoders[col] = le

    X_train = train_df.drop(columns=["target"])
    y_train = train_df["target"]
    X_test = test_df.drop(columns=["target"])
    y_test = test_df["target"]

    return X_train, y_train, X_test, y_test, train_labels, test_labels, encoders


if __name__ == "__main__":
    X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
        "data/nsl-kdd/KDDTrain+.txt",
        "data/nsl-kdd/KDDTest+.txt",
    )

    print(f"X_train : {X_train.shape}")
    print(f"X_test  : {X_test.shape}")
    print(f"\nDistribution y_train : {y_train.value_counts().to_dict()}")
    print(f"Distribution y_test  : {y_test.value_counts().to_dict()}")
    print(f"\nColonnes finales ({len(X_train.columns)}) :")
    print(list(X_train.columns))
