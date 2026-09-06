"""
Tests de risk_scorer.py — ensemble XGBoost (supervisé) + Isolation Forest
(non supervisé), combinés par un OU logique.

Les tests utilisent des modèles factices à sorties imposées plutôt que
les modèles entraînés. Deux raisons : la suite doit tourner sur un clone
neuf sans les artefacts d'entraînement ni NSL-KDD, et surtout ce qui est
testé ici est la LOGIQUE DE COMBINAISON, pas la qualité des modèles.
Charger les vrais modèles rendrait le test dépendant de leurs
performances et donc incapable d'isoler une régression du OU.

Le RiskScorer est construit par object.__new__ car son __init__ lit des
fichiers sur disque ; les attributs sont ensuite posés explicitement,
ce qui documente exactement de quoi la logique dépend.
"""

import numpy as np
import pandas as pd
import pytest

from feature_schema import NSL_KDD_FEATURE_COLUMNS, FeatureSchemaError
from risk_scorer import OPERATIONAL_THRESHOLD, RISK_BANDS, RiskScorer


class FakeXGB:
    """Renvoie les probabilités d'attaque qu'on lui impose."""

    def __init__(self, attack_probabilities):
        self.attack_probabilities = np.asarray(attack_probabilities, dtype=float)

    def predict_proba(self, X):
        p = self.attack_probabilities[: len(X)]
        return np.column_stack([1.0 - p, p])


class FakeIsolationForest:
    """predict() renvoie -1 pour une anomalie, 1 sinon (convention sklearn)."""

    def __init__(self, anomaly_flags):
        self.anomaly_flags = np.asarray(anomaly_flags, dtype=int)

    def predict(self, X):
        return np.where(self.anomaly_flags[: len(X)] == 1, -1, 1)


def make_X(n_rows: int) -> pd.DataFrame:
    return pd.DataFrame(
        {col: [0.0] * n_rows for col in NSL_KDD_FEATURE_COLUMNS},
        columns=NSL_KDD_FEATURE_COLUMNS,
    )


def make_scorer(attack_probabilities, anomaly_flags=None) -> RiskScorer:
    scorer = object.__new__(RiskScorer)
    scorer.model = FakeXGB(attack_probabilities)
    scorer.use_ensemble = anomaly_flags is not None
    scorer.iso_model = FakeIsolationForest(anomaly_flags) if anomaly_flags else None
    return scorer


class TestScoreContinu:
    def test_le_score_provient_du_seul_xgboost(self):
        """
        Le score continu reste XGBoost pur, même en ensemble : c'est le
        signal de priorisation fine. L'ensemble n'intervient qu'au niveau
        de la décision binaire.
        """
        probabilities = [0.05, 0.42, 0.91]
        scorer = make_scorer(probabilities, anomaly_flags=[1, 1, 1])
        scores = scorer.score(make_X(3))
        assert np.allclose(scores.to_numpy(), probabilities)

    def test_l_index_du_dataframe_est_conserve(self):
        """
        assess() réaligne plusieurs Series par index. Un index perdu
        produirait des lignes silencieusement décalées.
        """
        X = make_X(3)
        X.index = [10, 20, 30]
        scores = make_scorer([0.1, 0.2, 0.3]).score(X)
        assert list(scores.index) == [10, 20, 30]


class TestLogiqueOU:
    """
    Table de vérité du OU. C'est le cœur du module : XGBoost plafonne sur
    les types d'attaque absents de son entraînement, Isolation Forest ne
    partage pas cette limite, et le OU est ce qui fait passer le rappel
    de 70% à 77,5%.
    """

    @pytest.mark.parametrize("proba,anomaly,expected", [
        (0.9, 0, 1),   # XGBoost seul déclenche
        (0.1, 1, 1),   # Isolation Forest seul rattrape
        (0.9, 1, 1),   # les deux
        (0.1, 0, 0),   # aucun
    ])
    def test_table_de_verite(self, proba, anomaly, expected):
        scorer = make_scorer([proba], anomaly_flags=[anomaly])
        assert int(scorer.classify(make_X(1)).iloc[0]) == expected

    def test_sans_ensemble_seul_xgboost_decide(self):
        """Isolation Forest absent : le rattrapage ne doit pas avoir lieu."""
        scorer = make_scorer([0.1])
        assert int(scorer.classify(make_X(1)).iloc[0]) == 0

    def test_le_seuil_operationnel_est_applique(self):
        """Le seuil est inclusif : score >= seuil déclenche."""
        just_below = OPERATIONAL_THRESHOLD - 0.01
        scorer = make_scorer([just_below, OPERATIONAL_THRESHOLD])
        assert list(scorer.classify(make_X(2))) == [0, 1]


class TestTracabiliteAnomalie:
    def test_le_drapeau_ne_leve_que_pour_un_rattrapage_reel(self):
        """
        flagged_by_anomaly_detector doit valoir 1 UNIQUEMENT quand
        Isolation Forest rattrape ce que XGBoost a manqué. S'il levait
        aussi quand les deux concordent, il perdrait son sens : le
        dashboard et build_recommendation s'en servent pour signaler
        l'absence de signature connue.
        """
        scorer = make_scorer([0.9, 0.1, 0.9, 0.1], anomaly_flags=[1, 1, 0, 0])
        result = scorer.assess(make_X(4))
        assert list(result["flagged_by_anomaly_detector"]) == [0, 1, 0, 0]

    def test_assess_expose_les_colonnes_attendues(self):
        result = make_scorer([0.5], anomaly_flags=[0]).assess(make_X(1))
        assert set(result.columns) == {
            "risk_score", "risk_band", "is_attack", "flagged_by_anomaly_detector",
        }


class TestBandesDeRisque:
    @pytest.mark.parametrize("score,expected", [
        (0.0, "low"), (0.19, "low"),
        (0.2, "medium"), (0.49, "medium"),
        (0.5, "high"), (0.79, "high"),
        (0.8, "critical"), (1.0, "critical"),
    ])
    def test_bornes_des_bandes(self, score, expected):
        assert make_scorer([0.0]).risk_band(score) == expected

    def test_les_bandes_couvrent_l_intervalle_sans_trou(self):
        scorer = make_scorer([0.0])
        for value in np.arange(0.0, 1.001, 0.005):
            assert scorer.risk_band(float(value)) != "unknown", f"trou à {value}"

    def test_les_bandes_sont_contigues(self):
        """La borne haute de chaque bande est la borne basse de la suivante."""
        for (_, high, _), (low_next, _, _) in zip(RISK_BANDS, RISK_BANDS[1:]):
            assert high == low_next


class TestContratDeSchema:
    """
    Le garde-fou doit s'appliquer à CHAQUE méthode publique. Une seule
    méthode non protégée suffirait à rouvrir la porte à une prédiction
    silencieuse sur des features du mauvais schéma.
    """

    @pytest.mark.parametrize("method", ["score", "classify", "assess"])
    def test_un_schema_invalide_est_rejete(self, method):
        bad = pd.DataFrame({"event_count": [1], "unique_dest_ports": [2],
                            "inbound_event_count": [0]})
        scorer = make_scorer([0.5], anomaly_flags=[0])
        with pytest.raises(FeatureSchemaError):
            getattr(scorer, method)(bad)
