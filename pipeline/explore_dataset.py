"""
explore_dataset.py

Chargement et exploration initiale du dataset NSL-KDD.
"""

import pandas as pd

COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty_level",
]


def load_nsl_kdd(path: str) -> pd.DataFrame:
    """Charge un fichier NSL-KDD brut avec les noms de colonnes officiels."""
    df = pd.read_csv(path, names=COLUMN_NAMES)
    return df


if __name__ == "__main__":
    train_df = load_nsl_kdd("data/nsl-kdd/KDDTrain+.txt")
    test_df = load_nsl_kdd("data/nsl-kdd/KDDTest+.txt")

    print(f"Train : {train_df.shape[0]} lignes, {train_df.shape[1]} colonnes")
    print(f"Test  : {test_df.shape[0]} lignes, {test_df.shape[1]} colonnes\n")

    print("Répartition des labels (train) :")
    print(train_df["label"].value_counts().head(15))

    print(f"\nNombre de classes d'attaques distinctes (train) : {train_df['label'].nunique()}")

    print("\nRatio normal vs attaque (train) :")
    binary = train_df["label"].apply(lambda x: "normal" if x == "normal" else "attack")
    print(binary.value_counts(normalize=True))

    print("\nColonnes catégorielles :")
    print(train_df[["protocol_type", "service", "flag"]].nunique())
