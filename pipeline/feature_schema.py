"""
feature_schema.py

Contrat explicite du schéma de features attendu par les modèles entraînés
sur NSL-KDD (risk_scorer.py, tactic classifier). Sert de garde-fou avant
tout appel à predict()/predict_proba() : sans cette validation, un
DataFrame mal formé produit soit une exception cryptique venant des
internals XGBoost (dtype invalide), soit -- pire -- une prédiction
silencieuse et dénuée de sens si le nombre de colonnes correspond par
coïncidence sans que leur contenu ne corresponde.

Découverte du 15/08/2026 : le pipeline live (feature_extractor.py, 14
colonnes agrégées par fenêtre temporelle : event_count, unique_dest_ports,
etc.) et le schéma d'entraînement NSL-KDD (41 colonnes de détail par
session : duration, src_bytes, num_failed_logins, dst_host_serror_rate,
etc.) sont deux espaces de features fondamentalement différents, sans
recouvrement de noms ni d'équivalence conceptuelle directe. Le modèle
n'a donc jamais été exécuté avec succès sur des features live -- toute
validation antérieure (rapports, dashboard, démonstrations) portait
exclusivement sur des données NSL-KDD. Voir docs/journal-technique.md,
entrée du 15/08/2026, pour l'analyse complète et la feuille de route.

Ce module ne résout pas cet écart architectural (qui nécessiterait soit
une couche d'adaptation de features, soit un nouveau modèle entraîné
directement sur le schéma live). Il transforme un échec silencieux ou
cryptique en échec explicite et diagnostiqué, ce qui est le préalable
nécessaire à toute résolution ultérieure.
"""

from dataclasses import dataclass
import pandas as pd


class FeatureSchemaError(Exception):
    """
    Levée quand un DataFrame ne correspond pas au schéma de features
    attendu par un modèle entraîné sur NSL-KDD. Le message inclut un
    diagnostic actionnable (colonnes manquantes/en trop, dtypes invalides)
    plutôt qu'une trace d'appel interne à la librairie ML.
    """
    pass


# Schéma figé au 15/08/2026, dérivé de preprocess.py::preprocess() sur
# KDDTrain+.txt / KDDTest+.txt. Toute modification de preprocess.py qui
# change l'ensemble ou l'ordre des colonnes produites DOIT être répercutée
# ici -- utiliser verify_against_preprocess() (voir bas de fichier) pour
# détecter une dérive entre les deux.
NSL_KDD_FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

# Schéma des features produites par le pipeline live (feature_extractor.py),
# consigné ici uniquement pour que le message d'erreur puisse identifier
# ce cas précis et distinguer "colonnes live accidentellement passées à un
# modèle NSL-KDD" d'une erreur de schéma générique/inconnue.
LIVE_PIPELINE_FEATURE_COLUMNS = [
    "agent_name", "window_start", "window_minutes", "event_count",
    "unique_dest_ips", "unique_dest_ports", "distinct_rule_ids",
    "avg_rule_level", "max_rule_level", "suricata_ratio", "time_span_seconds",
    "inbound_event_count", "inbound_unique_src_ips", "inbound_unique_ports",
    "outbound_event_count", "outbound_unique_ports",
]


@dataclass
class SchemaValidationResult:
    is_valid: bool
    missing_columns: list
    unexpected_columns: list
    looks_like_live_pipeline: bool


def _check_schema(X: pd.DataFrame, expected_columns: list) -> SchemaValidationResult:
    actual = set(X.columns)
    expected = set(expected_columns)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    looks_like_live = len(set(LIVE_PIPELINE_FEATURE_COLUMNS) & actual) >= 3
    return SchemaValidationResult(
        is_valid=(not missing and not unexpected),
        missing_columns=missing,
        unexpected_columns=unexpected,
        looks_like_live_pipeline=looks_like_live,
    )


def validate_nsl_kdd_schema(X: pd.DataFrame, context: str = "") -> None:
    """
    Valide qu'un DataFrame correspond exactement au schéma NSL-KDD attendu
    par les modèles entraînés (risk_scorer, tactic classifier). Lève
    FeatureSchemaError avec un diagnostic complet si ce n'est pas le cas.

    context : description libre du point d'appel (ex: "RiskScorer.score"),
    incluse dans le message d'erreur pour faciliter le débogage.
    """
    result = _check_schema(X, NSL_KDD_FEATURE_COLUMNS)

    if result.is_valid:
        return

    lines = [
        f"Schéma de features invalide{f' ({context})' if context else ''} : "
        f"ce modèle est entraîné sur le schéma NSL-KDD ({len(NSL_KDD_FEATURE_COLUMNS)} "
        f"colonnes) et ne peut pas produire de prédiction fiable sur un schéma différent.",
    ]

    if result.looks_like_live_pipeline:
        lines.append(
            "\nCe DataFrame ressemble aux features du pipeline live "
            "(feature_extractor.py) plutôt qu'à une sortie de preprocess.py. "
            "C'est un écart architectural connu, pas une erreur de code isolée : "
            "le pipeline live produit des agrégats par fenêtre temporelle "
            "(ex: event_count, unique_dest_ports) tandis que ce modèle attend "
            "des métriques détaillées par session (ex: src_bytes, "
            "num_failed_logins, dst_host_serror_rate). Ces deux schémas ne "
            "sont pas convertibles l'un vers l'autre sans une couche "
            "d'adaptation de features non encore développée. "
            "Voir docs/journal-technique.md, entrée du 15/08/2026."
        )

    if result.missing_columns:
        lines.append(f"\nColonnes attendues absentes ({len(result.missing_columns)}) : "
                      f"{result.missing_columns}")
    if result.unexpected_columns:
        lines.append(f"\nColonnes présentes non attendues ({len(result.unexpected_columns)}) : "
                      f"{result.unexpected_columns}")

    raise FeatureSchemaError("\n".join(lines))


def verify_against_preprocess() -> bool:
    """
    Utilitaire de maintenance : compare NSL_KDD_FEATURE_COLUMNS (figé dans
    ce module) au schéma réellement produit par preprocess.py aujourd'hui.
    À exécuter après toute modification de preprocess.py pour détecter une
    dérive. Retourne True si les deux schémas sont identiques (même
    colonnes, même ordre).
    """
    from preprocess import preprocess

    _, _, X_test, *_ = preprocess(
        "data/nsl-kdd/KDDTrain+.txt",
        "data/nsl-kdd/KDDTest+.txt",
    )
    actual = list(X_test.columns)

    if actual == NSL_KDD_FEATURE_COLUMNS:
        print("OK : NSL_KDD_FEATURE_COLUMNS correspond exactement à la sortie actuelle de preprocess().")
        return True

    print("DÉRIVE DÉTECTÉE entre feature_schema.py et preprocess.py :")
    if set(actual) != set(NSL_KDD_FEATURE_COLUMNS):
        print("  Colonnes différentes (pas seulement un problème d'ordre).")
        print("  Absentes de preprocess() actuel :", sorted(set(NSL_KDD_FEATURE_COLUMNS) - set(actual)))
        print("  Nouvelles dans preprocess() actuel :", sorted(set(actual) - set(NSL_KDD_FEATURE_COLUMNS)))
    else:
        print("  Mêmes colonnes, ordre différent -- à corriger dans NSL_KDD_FEATURE_COLUMNS.")
    return False


if __name__ == "__main__":
    verify_against_preprocess()
