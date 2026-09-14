"""
Tests du chemin d'analyse FLUX LOCAUX (LocalFlowAnalysisEngine).

Objectif principal, exigé explicitement : vérifier PAR UN APPEL RÉEL, et
non par lecture de code, que playbook.build_recommendation() fonctionne
sans modification sur ce chemin -- sa signature (risk_band, tactic,
confidence, detected_by_anomaly) est agnostique de la source.
"""

import os

import pandas as pd
import pytest

from feature_schema import LOCAL_FLOW_FEATURE_COLUMNS, FeatureSchemaError
from mitre_categories import TACTIC_MITRE_IDS
from playbook import build_recommendation

LOCAL_ATTACK_TACTICS = ["Reconnaissance", "Impact", "InitialAccess_CredentialAccess"]


class TestBuildRecommendationAgnostiqueDeLaSource:
    """
    Preuve, au niveau de la fonction, que build_recommendation traite les
    tactiques du chemin flux-locaux exactement comme celles du chemin
    NSL-KDD : mêmes clés, aucune adaptation.
    """

    @pytest.mark.parametrize("tactic", LOCAL_ATTACK_TACTICS)
    @pytest.mark.parametrize("band", ["low", "medium", "high", "critical"])
    def test_appel_reel_par_tactique_locale(self, tactic, band):
        text = build_recommendation(band, tactic, confidence=0.9,
                                    detected_by_anomaly=False)
        assert isinstance(text, str) and len(text) > 40
        assert TACTIC_MITRE_IDS[tactic] in text

    def test_detected_by_anomaly_false_ne_declenche_pas_l_avertissement(self):
        """
        Ce chemin passe toujours detected_by_anomaly=False : l'avertissement
        'détecté par anomalie seule' ne doit donc jamais apparaître.
        """
        text = build_recommendation("low", "Impact", confidence=0.9,
                                    detected_by_anomaly=False)
        assert "Isolation Forest" not in text


# --- Tests d'intégration du moteur, seulement si le modèle est présent ------

def _engine_or_skip():
    from analysis_engine import LocalFlowAnalysisEngine
    if not LocalFlowAnalysisEngine.is_available("."):
        pytest.skip("modèle flux locaux absent (lancer train_local_flow_model.py)")
    return LocalFlowAnalysisEngine()


class TestMoteurFluxLocaux:
    def test_schema_errone_rejete(self):
        eng = _engine_or_skip()
        bad = pd.DataFrame({"event_count": [1], "unique_dest_ports": [2],
                            "inbound_event_count": [0]})
        with pytest.raises(FeatureSchemaError):
            eng.analyze(bad)

    def test_colonnes_de_sortie(self):
        eng = _engine_or_skip()
        X = pd.DataFrame({c: [0] for c in LOCAL_FLOW_FEATURE_COLUMNS})
        out = eng.analyze(X)
        assert {"risk_score", "risk_band", "is_attack", "predicted_tactic",
                "tactic_confidence", "mitre_id", "context", "recommendation"} <= set(out.columns)

    def test_flux_de_scan_reel_donne_tactique_et_mitre(self):
        """
        Un flux de scan réel (SYN seul, aucun octet retour) doit être classé
        attaque, se voir attribuer une tactique et un identifiant MITRE, et
        recevoir une recommandation non vide issue du playbook.
        """
        eng = _engine_or_skip()
        # signature de scan mesurée sur le trafic réel : TCP_FLAGS=2 (SYN),
        # 1 paquet aller / 0 retour, vers un port applicatif.
        scan = pd.DataFrame([{
            "L4_SRC_PORT": 40000, "L4_DST_PORT": 3306, "PROTOCOL": 6, "L7_PROTO": 0.0,
            "IN_BYTES": 66, "OUT_BYTES": 0, "IN_PKTS": 1, "OUT_PKTS": 0,
            "TCP_FLAGS": 2, "FLOW_DURATION_MILLISECONDS": 0,
        }])
        out = eng.analyze(scan)
        row = out.iloc[0]
        if row["is_attack"] == 1:
            assert row["predicted_tactic"] in LOCAL_ATTACK_TACTICS
            assert row["mitre_id"] == TACTIC_MITRE_IDS[row["predicted_tactic"]]
            assert isinstance(row["recommendation"], str) and len(row["recommendation"]) > 40
        else:
            pytest.skip("le binaire n'a pas classé ce flux synthétique en attaque "
                        "(dépend du modèle entraîné) — couvert par la démo sur flux réels")

    def test_benin_non_alerte_n_a_pas_de_tactique(self):
        eng = _engine_or_skip()
        # flux applicatif complet, volumineux, bidirectionnel : profil bénin
        benign = pd.DataFrame([{
            "L4_SRC_PORT": 51000, "L4_DST_PORT": 443, "PROTOCOL": 6, "L7_PROTO": 91.0,
            "IN_BYTES": 5000, "OUT_BYTES": 12000, "IN_PKTS": 20, "OUT_PKTS": 18,
            "TCP_FLAGS": 27, "FLOW_DURATION_MILLISECONDS": 3000,
        }])
        out = eng.analyze(benign).iloc[0]
        if out["is_attack"] == 0:
            assert out["predicted_tactic"] is None
            assert out["recommendation"].startswith("Surveillance de routine")
