"""
analysis_engine.py

Module d'assemblage final : combine le score de risque (modèle binaire),
la tactique MITRE probable (modèle multi-classe), et génère un contexte
d'analyse + une recommandation lisible pour un analyste SOC.

C'est le point d'entrée unique du moteur de détection intelligent.
"""

import logging
import xgboost as xgb
import pandas as pd
import joblib

from risk_scorer import RiskScorer, OPERATIONAL_THRESHOLD
from mitre_categories import TACTIC_MITRE_IDS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("analysis_engine")

TACTIC_DESCRIPTIONS = {
    "Impact": "Tentative de perturbation de la disponibilité du système ou du service (déni de service).",
    "Reconnaissance": "Activité de sondage ou de collecte d'informations en préparation d'une attaque.",
    "InitialAccess_CredentialAccess": "Tentative d'accès non autorisé ou de compromission d'identifiants.",
    "PrivilegeEscalation": "Tentative d'obtention de privilèges système supérieurs.",
}

RECOMMENDATIONS = {
    ("critical", "Impact"): "Vérifier immédiatement la disponibilité des services critiques. Envisager un blocage temporaire de la source si le trafic persiste.",
    ("critical", "Reconnaissance"): "Isoler la source si possible. Vérifier les logs des systèmes ciblés pour une activité de suivi (exploitation post-scan).",
    ("critical", "InitialAccess_CredentialAccess"): "Vérifier immédiatement les journaux d'authentification. Forcer une rotation des identifiants si compromission suspectée.",
    ("critical", "PrivilegeEscalation"): "Investigation prioritaire : vérifier l'intégrité du système, les processus en cours et les modifications récentes de permissions.",
    ("high", "Impact"): "Surveiller l'évolution du trafic. Préparer une réponse si l'activité s'intensifie.",
    ("high", "Reconnaissance"): "Documenter la source pour corrélation future. Surveillance renforcée recommandée.",
    ("high", "InitialAccess_CredentialAccess"): "Vérifier les tentatives d'authentification récentes associées à cette source.",
    ("high", "PrivilegeEscalation"): "Vérification manuelle recommandée — signal faible mais catégorie à haut impact potentiel.",
}

DEFAULT_RECOMMENDATION = "Surveillance de routine — aucune action immédiate requise."


class AnalysisEngine:
    """Point d'entrée unique du moteur de détection : score + tactique + contexte."""

    def __init__(
        self,
        risk_model_path: str = "data/xgboost_baseline.json",
        iso_model_path: str = "data/isolation_forest.pkl",
        tactic_model_path: str = "data/xgboost_tactic_classifier_final.json",
        tactic_encoder_path: str = "data/tactic_label_encoder.pkl",
        use_ensemble: bool = True,
    ):
        self.risk_scorer = RiskScorer(
            xgb_model_path=risk_model_path,
            iso_model_path=iso_model_path,
            use_ensemble=use_ensemble,
        )

        self.tactic_model = xgb.XGBClassifier()
        self.tactic_model.load_model(tactic_model_path)
        self.tactic_encoder = joblib.load(tactic_encoder_path)

        logger.info("Moteur d'analyse initialisé (modèle de risque + modèle de tactique).")

    def analyze(self, X: pd.DataFrame, true_labels: pd.Series = None) -> pd.DataFrame:
        """
        Analyse complète : pour chaque échantillon, calcule le score de
        risque, et si suspect, prédit la tactique MITRE probable avec
        contexte et recommandation.
        """
        risk_assessment = self.risk_scorer.assess(X)

        suspicious_mask = risk_assessment["is_attack"] == 1
        X_suspicious = X[suspicious_mask]

        tactic_results = pd.DataFrame(
            index=X.index,
            columns=["predicted_tactic", "tactic_confidence", "mitre_id", "context", "recommendation"],
        )

        if len(X_suspicious) > 0:
            tactic_proba = self.tactic_model.predict_proba(X_suspicious)
            tactic_pred_idx = tactic_proba.argmax(axis=1)
            tactic_confidence = tactic_proba.max(axis=1)
            tactic_names = self.tactic_encoder.inverse_transform(tactic_pred_idx)

            tactic_results.loc[X_suspicious.index, "predicted_tactic"] = tactic_names
            tactic_results.loc[X_suspicious.index, "tactic_confidence"] = tactic_confidence
            tactic_results.loc[X_suspicious.index, "mitre_id"] = [
                TACTIC_MITRE_IDS.get(t, "N/A") for t in tactic_names
            ]
            tactic_results.loc[X_suspicious.index, "context"] = [
                TACTIC_DESCRIPTIONS.get(t, "Contexte non disponible.") for t in tactic_names
            ]

            risk_bands = risk_assessment.loc[X_suspicious.index, "risk_band"]
            recommendations = [
                RECOMMENDATIONS.get((band, tactic), DEFAULT_RECOMMENDATION)
                for band, tactic in zip(risk_bands, tactic_names)
            ]
            tactic_results.loc[X_suspicious.index, "recommendation"] = recommendations

        tactic_results.loc[~suspicious_mask, "recommendation"] = DEFAULT_RECOMMENDATION

        result = pd.concat([risk_assessment, tactic_results], axis=1)

        if true_labels is not None:
            result["true_label"] = true_labels.values

        return result


if __name__ == "__main__":
    from preprocess import preprocess

    X_train, y_train, X_test, y_test, train_labels, test_labels, encoders = preprocess(
        "data/nsl-kdd/KDDTrain+.txt",
        "data/nsl-kdd/KDDTest+.txt",
    )

    engine = AnalysisEngine()

    # Échantillon varié pour la démo : quelques attaques connues et inconnues + normal
    sample_indices = [0, 1, 2, 3, 4, 7, 9, 20, 50, 100]
    X_sample = X_test.iloc[sample_indices]
    labels_sample = test_labels.iloc[sample_indices]

    results = engine.analyze(X_sample, true_labels=labels_sample)

    pd.set_option("display.max_colwidth", 50)
    print("\n=== Résultat de l'analyse complète ===\n")
    for idx, row in results.iterrows():
        print(f"--- Événement (vrai label: {row['true_label']}) ---")
        print(f"  Score de risque    : {row['risk_score']:.4f} ({row['risk_band']})")
        if pd.notna(row['predicted_tactic']):
            print(f"  Tactique prédite   : {row['predicted_tactic']} "
                  f"(confiance: {row['tactic_confidence']:.2f}, MITRE: {row['mitre_id']})")
            print(f"  Contexte           : {row['context']}")
        print(f"  Recommandation     : {row['recommendation']}")
        print()
