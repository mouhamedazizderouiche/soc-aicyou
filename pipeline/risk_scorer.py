"""
risk_scorer.py

Module de scoring de risque : encapsule le modèle XGBoost (supervisé)
ET le modèle Isolation Forest (non-supervisé) en ensemble.

Rationale de l'ensemble (voir isolation_forest_hypothesis_test.py) :
XGBoost a un plafond de recall structurel sur les types d'attaque
absents de l'entraînement (48% de recall sur ces types précisément).
Isolation Forest, entraîné uniquement sur du trafic normal, ne
partage pas cette limite (66% de recall sur les mêmes types) car il
détecte des écarts au comportement normal plutôt que des signatures
d'attaque apprises. Combinés (logique OR), le système passe de 70%
à 77.5% de recall global, pour un coût FPR modeste (2.99% -> 3.58%).

Le score continu (predict_proba pour XGBoost) est toujours conservé
et transmis, même quand une classification binaire est demandée —
la priorisation finale doit rester pilotable par un humain (analyste
SOC), pas figée dans une coupure binaire stricte.

Contrat de schéma (ajouté 15/08/2026) : chaque méthode publique valide
explicitement que X correspond au schéma NSL-KDD attendu avant tout
appel au modèle. Découvert le 15/08/2026 : appeler ce module avec des
features du pipeline live (feature_extractor.py, schéma différent,
sans recouvrement) provoquait soit un crash XGBoost cryptique (dtype
non numérique), soit -- pire, si le nombre de colonnes avait coïncidé
-- une prédiction silencieuse et dénuée de sens. Voir feature_schema.py
et docs/journal-technique.md (entrée du 15/08/2026) pour l'analyse
complète de cet écart architectural, non résolu par cette validation
mais rendu explicite et diagnostiqué au lieu de silencieux.
"""

import logging
import joblib
import xgboost as xgb
import pandas as pd

from feature_schema import validate_nsl_kdd_schema

logger = logging.getLogger("risk_scorer")

# Seuil retenu après analyse (voir threshold_analysis.py) : compromis
# recall/precision adapté à un contexte SOC pour le modèle XGBoost seul.
OPERATIONAL_THRESHOLD = 0.3

RISK_BANDS = [
    (0.0, 0.2, "low"),
    (0.2, 0.5, "medium"),
    (0.5, 0.8, "high"),
    (0.8, 1.01, "critical"),
]


class RiskScorer:
    """Encapsule le modèle XGBoost + Isolation Forest (ensemble) et la logique de scoring."""

    def __init__(
        self,
        xgb_model_path: str = "data/xgboost_baseline.json",
        iso_model_path: str = "data/isolation_forest.pkl",
        use_ensemble: bool = True,
    ):
        self.model = xgb.XGBClassifier()
        self.model.load_model(xgb_model_path)
        logger.info("Modèle XGBoost chargé depuis %s", xgb_model_path)

        self.use_ensemble = use_ensemble
        self.iso_model = None
        if use_ensemble:
            try:
                self.iso_model = joblib.load(iso_model_path)
                logger.info("Modèle Isolation Forest chargé depuis %s", iso_model_path)
            except FileNotFoundError:
                logger.warning(
                    "Isolation Forest introuvable (%s) — ensemble désactivé, "
                    "retour au XGBoost seul. Lancer train_isolation_forest.py.",
                    iso_model_path,
                )
                self.use_ensemble = False

    def score(self, X: pd.DataFrame) -> pd.Series:
        """
        Retourne le score de risque continu (0-1) pour chaque échantillon.
        Ce score reste basé sur XGBoost uniquement (predict_proba) : c'est
        le signal continu utilisé pour la priorisation fine (bandes de
        risque). L'ensemble intervient au niveau de la classification
        binaire (classify/assess), pas du score continu.
        """
        validate_nsl_kdd_schema(X, context="RiskScorer.score")
        return pd.Series(self.model.predict_proba(X)[:, 1], index=X.index)

    def _iso_flags(self, X: pd.DataFrame) -> pd.Series:
        """Retourne 1 si Isolation Forest juge l'échantillon anormal, 0 sinon."""
        if self.iso_model is None:
            return pd.Series([0] * len(X), index=X.index)
        validate_nsl_kdd_schema(X, context="RiskScorer._iso_flags")
        raw_pred = self.iso_model.predict(X)  # -1 = anomalie, 1 = normal
        return pd.Series((raw_pred == -1).astype(int), index=X.index)

    def classify(self, X: pd.DataFrame, threshold: float = OPERATIONAL_THRESHOLD) -> pd.Series:
        """
        Classification binaire. Si l'ensemble est actif : attaque si
        XGBoost dépasse le seuil OU si Isolation Forest détecte une
        anomalie (logique OR, validée empiriquement dans
        ensemble_evaluation.py).
        """
        xgb_flags = (self.score(X) >= threshold).astype(int)
        if not self.use_ensemble:
            return xgb_flags
        iso_flags = self._iso_flags(X)
        return ((xgb_flags == 1) | (iso_flags == 1)).astype(int)

    def risk_band(self, score: float) -> str:
        """Convertit un score continu en bande de risque lisible."""
        for low, high, label in RISK_BANDS:
            if low <= score < high:
                return label
        return "unknown"

    def assess(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        Évaluation complète : score continu (XGBoost), bande de risque,
        décision binaire (ensemble si actif), et flag indiquant si c'est
        Isolation Forest qui a rattrapé une attaque manquée par XGBoost
        (utile pour la traçabilité/l'explicabilité de la décision).
        """
        validate_nsl_kdd_schema(X, context="RiskScorer.assess")

        scores = self.score(X)
        xgb_flags = (scores >= OPERATIONAL_THRESHOLD).astype(int)
        iso_flags = self._iso_flags(X) if self.use_ensemble else pd.Series([0] * len(X), index=X.index)

        is_attack = ((xgb_flags == 1) | (iso_flags == 1)).astype(int)
        caught_by_iso_only = ((xgb_flags == 0) & (iso_flags == 1)).astype(int)

        result = pd.DataFrame({
            "risk_score": scores,
            "risk_band": scores.apply(self.risk_band),
            "is_attack": is_attack,
            "flagged_by_anomaly_detector": caught_by_iso_only,
        }, index=X.index)
        return result


if __name__ == "__main__":
    from preprocess import preprocess

    X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
        "data/nsl-kdd/KDDTrain+.txt",
        "data/nsl-kdd/KDDTest+.txt",
    )

    scorer = RiskScorer()
    assessment = scorer.assess(X_test)

    print("=== Aperçu de l'évaluation (10 premiers échantillons) ===\n")
    preview = assessment.copy()
    preview["true_label"] = test_labels.values
    print(preview.head(10).to_string())

    print("\n=== Répartition par bande de risque ===")
    print(assessment["risk_band"].value_counts())

    print(f"\n=== Alertes rattrapées par Isolation Forest seul (XGBoost les avait manquées) ===")
    caught_count = assessment["flagged_by_anomaly_detector"].sum()
    print(f"{caught_count} événements ({caught_count/len(assessment):.1%} du total)")
