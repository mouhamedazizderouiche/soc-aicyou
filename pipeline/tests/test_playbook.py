"""
Tests de playbook.py — génération de recommandations ancrées dans le
playbook de réponse aux incidents.

L'enjeu de ces tests n'est pas de figer la formulation exacte des textes
(elle évoluera avec le playbook) mais de garantir les propriétés dont
dépend la décision d'un analyste : qu'une bande critique déclenche bien
les actions L2, qu'une confiance faible soit signalée, et surtout que le
signal « détecté par le seul détecteur d'anomalies » ne soit pas perdu
là où il compte le plus.
"""

import itertools

import pytest

from playbook import PLAYBOOKS, SLA_TARGETS, build_recommendation

TACTICS = list(PLAYBOOKS.keys())
BANDS = ["low", "medium", "high", "critical"]


class TestCouvertureCombinatoire:
    @pytest.mark.parametrize(
        "band,tactic,anomaly",
        list(itertools.product(BANDS, TACTICS, [False, True])),
    )
    def test_toute_combinaison_produit_un_texte_exploitable(self, band, tactic, anomaly):
        """
        Aucune combinaison bande × tactique × drapeau d'anomalie ne doit
        produire de texte vide, de None, ou d'exception : cette fonction
        alimente directement l'affichage analyste.
        """
        text = build_recommendation(band, tactic, confidence=0.8,
                                     detected_by_anomaly=anomaly)
        assert isinstance(text, str)
        assert len(text) > 40
        assert "None" not in text

    @pytest.mark.parametrize("tactic", TACTICS)
    def test_l_identifiant_mitre_est_toujours_present(self, tactic):
        text = build_recommendation("critical", tactic, confidence=0.9)
        assert PLAYBOOKS[tactic]["mitre_id"] in text


class TestAnomalieSeuleEnBandeBasse:
    """
    Le cas qui motive l'ordre des tests dans build_recommendation.

    Une alerte rattrapée par Isolation Forest seul a, par construction, un
    score XGBoost bas — c'est précisément pourquoi Isolation Forest a dû
    la rattraper. Elle tombe donc presque toujours en bande low/medium.
    Si le court-circuit low/medium s'appliquait avant l'examen du drapeau
    d'anomalie, le signal serait effacé exactement dans le cas où il est
    le seul signal disponible.
    """

    @pytest.mark.parametrize("band", ["low", "medium"])
    @pytest.mark.parametrize("tactic", TACTICS)
    def test_anomalie_seule_declenche_une_verification(self, band, tactic):
        text = build_recommendation(band, tactic, confidence=0.2,
                                     detected_by_anomaly=True)
        assert "Isolation Forest" in text
        assert "Verification L1" in text or "vérification L1" in text.lower()

    @pytest.mark.parametrize("band", ["low", "medium"])
    @pytest.mark.parametrize("tactic", TACTICS)
    def test_anomalie_seule_n_est_pas_traitee_en_surveillance_passive(self, band, tactic):
        """La régression que ces tests existent pour empêcher."""
        text = build_recommendation(band, tactic, confidence=0.2,
                                     detected_by_anomaly=True)
        assert "Surveillance passive" not in text

    @pytest.mark.parametrize("band", ["low", "medium"])
    def test_sans_anomalie_la_bande_basse_reste_passive(self, band):
        """Le contrepoint : sans ce signal, la bande basse reste passive."""
        text = build_recommendation(band, "Reconnaissance", confidence=0.9,
                                     detected_by_anomaly=False)
        assert "Surveillance passive" in text
        assert "Isolation Forest" not in text


class TestEscaladeParBande:
    @pytest.mark.parametrize("tactic", TACTICS)
    def test_critical_porte_les_actions_l1_et_l2(self, tactic):
        text = build_recommendation("critical", tactic, confidence=0.9)
        assert "Actions L1" in text
        assert "Actions L2" in text
        assert SLA_TARGETS["critical"] in text

    @pytest.mark.parametrize("tactic", TACTICS)
    def test_high_porte_l1_sans_l2(self, tactic):
        """
        L2 est du confinement (blocage UFW, isolation machine). Le
        déclencher en bande 'high' banaliserait des actions à impact.
        """
        text = build_recommendation("high", tactic, confidence=0.9)
        assert "Actions L1" in text
        assert "Actions L2" not in text
        assert SLA_TARGETS["high"] in text

    def test_le_sla_est_annonce_comme_non_applicable(self):
        """
        Transparence : les SLA sont des cibles documentées, pas des
        engagements — aucun mécanisme d'alerte n'existe. Le texte ne doit
        pas laisser croire l'inverse.
        """
        text = build_recommendation("critical", "Impact", confidence=0.9)
        assert "aucun mecanisme d'alerte n'existe" in text


class TestSignauxDeConfiance:
    def test_confiance_faible_est_signalee(self):
        text = build_recommendation("critical", "Impact", confidence=0.3)
        assert "Confiance de classification de tactique faible" in text

    def test_confiance_elevee_ne_declenche_pas_l_avertissement(self):
        text = build_recommendation("critical", "Impact", confidence=0.95)
        assert "Confiance de classification de tactique faible" not in text

    def test_la_confiance_est_affichee_en_pourcentage(self):
        text = build_recommendation("critical", "Impact", confidence=0.87)
        assert "87%" in text


class TestLimitesConnues:
    def test_privilege_escalation_affiche_sa_faiblesse(self):
        """
        Le classifieur est faible sur cette tactique (F1 = 0.19). La
        recommandation doit le dire, sinon un analyste accorderait au
        score une confiance qu'il ne mérite pas.
        """
        text = build_recommendation("critical", "PrivilegeEscalation", confidence=0.9)
        assert "Limite connue" in text
        assert "0.19" in text

    def test_impact_signale_son_absence_de_validation_live(self):
        text = build_recommendation("critical", "Impact", confidence=0.9)
        assert "Limite connue" in text
        assert "JAMAIS valide" in text

    def test_reconnaissance_validee_n_affiche_pas_de_limite(self):
        text = build_recommendation("critical", "Reconnaissance", confidence=0.9)
        assert "Limite connue" not in text


class TestTactiqueInconnue:
    def test_tactique_absente_du_playbook_retombe_sur_le_defaut(self):
        """
        Repli sûr : une tactique non couverte ne doit pas produire de
        recommandation inventée, ni lever d'exception dans le dashboard.
        """
        text = build_recommendation("critical", "TactiqueQuiNExistePas",
                                     confidence=0.9)
        assert "Surveillance de routine" in text

    def test_bande_inconnue_ne_leve_pas(self):
        text = build_recommendation("bande_inexistante", "Impact", confidence=0.9)
        assert isinstance(text, str) and text


def test_toutes_les_tactiques_du_playbook_ont_les_champs_requis():
    """
    Contrat de structure : analysis_engine et build_recommendation lisent
    ces clés sans garde. Une entrée incomplète casserait à l'exécution.
    """
    required = {"mitre_id", "techniques", "log_sources", "key_indicators",
                "escalation_criteria", "l1_actions", "l2_actions",
                "validation_status", "limitations"}
    for tactic, entry in PLAYBOOKS.items():
        assert required <= set(entry), f"{tactic} : clés manquantes"
        assert entry["l1_actions"] and entry["l2_actions"], f"{tactic} : actions vides"
        assert entry["validation_status"] in {"validated", "untested", "weak_model"}
