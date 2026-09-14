"""
analysis_engine.py

Module d'assemblage final : combine le score de risque (modèle binaire),
la tactique MITRE probable (modèle multi-classe), et génère un contexte
d'analyse + une recommandation lisible pour un analyste SOC.

C'est le point d'entrée unique du moteur de détection intelligent.

Les recommandations sont désormais générées par playbook.py
(build_recommendation), ancrées dans docs/playbook-reponse-incidents.md,
plutôt que par une table statique déconnectée du document de référence.
"""

import logging
import xgboost as xgb
import pandas as pd
import joblib

from risk_scorer import RiskScorer, OPERATIONAL_THRESHOLD
from mitre_categories import TACTIC_MITRE_IDS
from playbook import build_recommendation

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("analysis_engine")

TACTIC_DESCRIPTIONS = {
    "Impact": "Tentative de perturbation de la disponibilité du système ou du service (déni de service).",
    "Reconnaissance": "Activité de sondage ou de collecte d'informations en préparation d'une attaque.",
    "InitialAccess_CredentialAccess": "Tentative d'accès non autorisé ou de compromission d'identifiants.",
    "PrivilegeEscalation": "Tentative d'obtention de privilèges système supérieurs.",
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
            anomaly_flags = risk_assessment.loc[X_suspicious.index, "flagged_by_anomaly_detector"]

            recommendations = [
                build_recommendation(band, tactic, confidence, bool(anomaly_flag))
                for band, tactic, confidence, anomaly_flag in zip(
                    risk_bands, tactic_names, tactic_confidence, anomaly_flags
                )
            ]
            tactic_results.loc[X_suspicious.index, "recommendation"] = recommendations

        tactic_results.loc[~suspicious_mask, "recommendation"] = DEFAULT_RECOMMENDATION

        result = pd.concat([risk_assessment, tactic_results], axis=1)

        if true_labels is not None:
            result["true_label"] = true_labels.values

        return result


# =============================================================================
# Second chemin d'analyse : FLUX LOCAUX (schéma NetFlow v1)
# =============================================================================
# Ajouté le 09/09/2026. Ce chemin est DISTINCT du chemin NSL-KDD ci-dessus,
# qui n'est pas supprimé : l'un (NSL-KDD) est validé sur dataset académique
# et démontré sur la page "Moteur d'analyse" ; l'autre (flux locaux) est
# destiné au trafic réel, entraîné directement dessus (train_local_flow_model.py).
# Les deux coexistent volontairement.

import os as _os

from feature_schema import LOCAL_FLOW_FEATURE_COLUMNS, validate_local_flow_schema

# Bandes de risque : réutilisées telles quelles depuis risk_scorer, pour que
# le vocabulaire (low/medium/high/critical) soit identique sur les deux chemins.
from risk_scorer import RISK_BANDS

# Les trois tactiques d'attaque que le modèle multi-classe local peut prédire.
# Benign est exclu de ce sous-ensemble : pour un flux jugé suspect par le
# binaire, on veut la tactique d'attaque la plus probable, pas "Benign".
_LOCAL_ATTACK_TACTICS = ["Reconnaissance", "Impact", "InitialAccess_CredentialAccess"]

_LOCAL_TACTIC_DESCRIPTIONS = {
    "Reconnaissance": "Activité de sondage/scan en préparation d'une attaque.",
    "Impact": "Tentative de perturbation de la disponibilité (déni de service).",
    "InitialAccess_CredentialAccess": "Tentative d'accès ou de compromission d'identifiants (force brute).",
}


def _risk_band(score: float) -> str:
    for low, high, label in RISK_BANDS:
        if low <= score < high:
            return label
    return "unknown"


class LocalFlowAnalysisEngine:
    """
    Moteur d'analyse pour le schéma des FLUX LOCAUX (NetFlow v1). Assemble,
    comme AnalysisEngine mais sur ce schéma : score de risque (binaire) +
    tactique MITRE (multi-classe) + contexte + recommandation playbook.

    Choix explicite sur detected_by_anomaly (voir build_recommendation) :
    ce chemin n'a PAS de détecteur d'anomalies (pas d'Isolation Forest).
    detected_by_anomaly est donc TOUJOURS False, et l'avertissement
    "détecté par anomalie seule" ne s'applique pas ici. Ce n'est pas un
    oubli : un Isolation Forest sur les flux bénins locaux serait un modèle
    supplémentaire à valider (il faudrait des attaques nouvelles tenues à
    l'écart pour mesurer son apport), non fait à ce stade. La signature de
    build_recommendation est agnostique de la source : elle fonctionne sans
    modification, ce qui est vérifié par test (tests/test_analysis_engine_local.py).
    """

    def __init__(
        self,
        binary_model_path: str = "data/netflow/netflow_local_xgboost_binary.json",
        multiclass_model_path: str = "data/netflow/netflow_local_xgboost_multiclass.json",
        classes_path: str = "data/netflow/netflow_local_classes.pkl",
        attack_threshold: float = 0.5,
    ):
        self.binary_model = xgb.XGBClassifier()
        self.binary_model.load_model(binary_model_path)
        self.multiclass_model = xgb.XGBClassifier()
        self.multiclass_model.load_model(multiclass_model_path)
        self.classes = list(joblib.load(classes_path))  # ex. [Benign, Reconnaissance, Impact, IA_CA]
        self.attack_threshold = attack_threshold
        # index des tactiques d'attaque dans l'espace de sortie multi-classe
        self._attack_cols = [self.classes.index(t) for t in _LOCAL_ATTACK_TACTICS]
        logger.info("Moteur flux locaux initialisé (binaire + multi-classe, seuil=%.2f).",
                    attack_threshold)

    @classmethod
    def is_available(cls, base_dir: str = ".") -> bool:
        """Vrai si les trois artefacts du modèle local existent."""
        return all(_os.path.exists(_os.path.join(base_dir, p)) for p in (
            "data/netflow/netflow_local_xgboost_binary.json",
            "data/netflow/netflow_local_xgboost_multiclass.json",
            "data/netflow/netflow_local_classes.pkl",
        ))

    def analyze(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        X : DataFrame au schéma LOCAL_FLOW_FEATURE_COLUMNS (10 colonnes,
        adresses IP exclues). Retourne, par flux : score de risque, bande,
        décision d'attaque, tactique prédite + confiance + identifiant MITRE,
        contexte et recommandation playbook.
        """
        validate_local_flow_schema(X, context="LocalFlowAnalysisEngine.analyze")

        proba_attack = self.binary_model.predict_proba(X)[:, 1]
        is_attack = (proba_attack >= self.attack_threshold).astype(int)

        out = pd.DataFrame(index=X.index)
        out["risk_score"] = proba_attack
        out["risk_band"] = [_risk_band(s) for s in proba_attack]
        out["is_attack"] = is_attack
        out["predicted_tactic"] = None
        out["tactic_confidence"] = float("nan")
        out["mitre_id"] = None
        out["context"] = None
        out["recommendation"] = DEFAULT_RECOMMENDATION

        suspicious = out.index[is_attack == 1]
        if len(suspicious) > 0:
            # tactique = argmax RESTREINT aux tactiques d'attaque (Benign exclu)
            proba_mc = self.multiclass_model.predict_proba(X.loc[suspicious])
            attack_proba = proba_mc[:, self._attack_cols]
            best = attack_proba.argmax(axis=1)
            confidence = attack_proba.max(axis=1)
            tactics = [_LOCAL_ATTACK_TACTICS[i] for i in best]

            out.loc[suspicious, "predicted_tactic"] = tactics
            out.loc[suspicious, "tactic_confidence"] = confidence
            out.loc[suspicious, "mitre_id"] = [TACTIC_MITRE_IDS.get(t, "N/A") for t in tactics]
            out.loc[suspicious, "context"] = [
                _LOCAL_TACTIC_DESCRIPTIONS.get(t, "Contexte non disponible.") for t in tactics
            ]
            out.loc[suspicious, "recommendation"] = [
                build_recommendation(band, tactic, conf, detected_by_anomaly=False)
                for band, tactic, conf in zip(
                    out.loc[suspicious, "risk_band"], tactics, confidence
                )
            ]
        return out


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
