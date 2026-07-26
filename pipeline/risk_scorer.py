"""
risk_scorer.py

Module de scoring de risque : encapsule le modèle XGBoost entraîné et
applique la logique de décision retenue (seuil opérationnel 0.3).

Le score continu (predict_proba) est toujours conservé et transmis,
même quand une classification binaire est demandée — la priorisation
finale doit rester pilotable par un humain (analyste SOC), pas figée
dans une coupure binaire arbitraire.
"""

import logging
import xgboost as xgb
import pandas as pd

logger = logging.getLogger("risk_scorer")

# Seuil retenu après analyse (voir threshold_analysis.py) :
# compromis recall/precision adapté à un contexte SOC, sans viser un
# recall irréaliste que le modèle ne peut pas structurellement atteindre.
OPERATIONAL_THRESHOLD = 0.3

RISK_BANDS = [
    (0.0, 0.2, "low"),
    (0.2, 0.5, "medium"),
    (0.5, 0.8, "high"),
    (0.8, 1.01, "critical"),  # 1.01 pour inclure le score 1.0
]


class RiskScorer:
    """Encapsule le modèle entraîné et la logique de scoring/priorisation."""

    def __init__(self, model_path: str = "data/xgboost_baseline.json"):
        self.model = xgb.XGBClassifier()
        self.model.load_model(model_path)
        logger.info("Modèle chargé depuis %s", model_path)

    def score(self, X: pd.DataFrame) -> pd.Series:
        """Retourne le score de risque continu (0-1) pour chaque échantillon."""
        return pd.Series(self.model.predict_proba(X)[:, 1], index=X.index)

    def classify(self, X: pd.DataFrame, threshold: float = OPERATIONAL_THRESHOLD) -> pd.Series:
        """Retourne une classification binaire selon le seuil opérationnel."""
        scores = self.score(X)
        return (scores >= threshold).astype(int)

    def risk_band(self, score: float) -> str:
        """Convertit un score continu en bande de risque lisible."""
        for low, high, label in RISK_BANDS:
            if low <= score < high:
                return label
        return "unknown"

    def assess(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        Évaluation complète : retourne un DataFrame avec score continu,
        bande de risque et décision binaire pour chaque échantillon.
        """
        scores = self.score(X)
        result = pd.DataFrame({
            "risk_score": scores,
            "risk_band": scores.apply(self.risk_band),
            "is_attack": (scores >= OPERATIONAL_THRESHOLD).astype(int),
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
