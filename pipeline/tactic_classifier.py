"""
tactic_classifier.py

Modèle multi-classe : prédit la tactique MITRE ATT&CK probable à
partir du comportement réseau observé (features NSL-KDD), entraîné
uniquement sur les échantillons identifiés comme attaques.

Contrairement à un lookup statique, ce modèle généralise à des
comportements jamais vus sous ce label exact — il apprend les
patterns réseau associés à chaque tactique, pas une correspondance
figée nom-d'attaque -> tactique.
"""

import xgboost as xgb
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix

from preprocess import preprocess
from mitre_categories import label_to_tactic


def build_tactic_dataset(X, labels):
    """
    Filtre pour ne garder que les échantillons d'attaque (exclut 'normal'
    et les labels non mappés), et associe la catégorie de tactique.
    """
    tactics = labels.apply(label_to_tactic)
    mask = tactics != "Unknown"
    mask = mask & (labels != "normal")

    return X[mask], tactics[mask]


if __name__ == "__main__":
    X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
        "data/nsl-kdd/KDDTrain+.txt",
        "data/nsl-kdd/KDDTest+.txt",
    )

    X_train_tactic, y_train_tactic_raw = build_tactic_dataset(X_train, train_labels)
    X_test_tactic, y_test_tactic_raw = build_tactic_dataset(X_test, test_labels)

    print(f"Échantillons d'entraînement (attaques uniquement) : {len(X_train_tactic)}")
    print(f"Échantillons de test (attaques uniquement) : {len(X_test_tactic)}")
    print(f"\nDistribution train :\n{y_train_tactic_raw.value_counts()}")
    print(f"\nDistribution test :\n{y_test_tactic_raw.value_counts()}")

    # Encodage des classes de tactiques (texte -> entier pour XGBoost)
    tactic_encoder = LabelEncoder()
    y_train_tactic = tactic_encoder.fit_transform(y_train_tactic_raw)

    # Gestion des classes potentiellement absentes du train mais présentes en test
    known_classes = set(tactic_encoder.classes_)
    mask_known = y_test_tactic_raw.isin(known_classes)
    X_test_tactic = X_test_tactic[mask_known]
    y_test_tactic_raw = y_test_tactic_raw[mask_known]
    y_test_tactic = tactic_encoder.transform(y_test_tactic_raw)

    print(f"\nClasses de tactiques : {list(tactic_encoder.classes_)}")

    model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        objective="multi:softprob",
        num_class=len(tactic_encoder.classes_),
        eval_metric="mlogloss",
        random_state=42,
    )

    print("\nEntraînement du modèle multi-classe...")
    model.fit(X_train_tactic, y_train_tactic)
    print("Terminé.\n")

    y_pred = model.predict(X_test_tactic)
    y_proba = model.predict_proba(X_test_tactic)

    print("=== Rapport de classification (par tactique) ===")
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

    model.save_model("data/xgboost_tactic_classifier.json")

    import joblib
    joblib.dump(tactic_encoder, "data/tactic_label_encoder.pkl")

    print("\nModèle et encodeur sauvegardés.")
