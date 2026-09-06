"""
Tests de mitre_categories.py — regroupement des labels d'attaque NSL-KDD
en tactiques MITRE ATT&CK.

Contexte : le 14/08/2026, la table ne couvrait que les 22 types présents
dans KDDTrain+. Le jeu de test NSL-KDD contient délibérément des types
absents de l'entraînement, et ces 17 types supplémentaires — 29,2% des
échantillons d'attaque du test — étaient silencieusement exclus de
l'évaluation par le filtre "Unknown". Ces tests verrouillent la
couverture pour que le trou ne se rouvre pas sans qu'on le voie.
"""

from collections import Counter

import pytest

from mitre_categories import TACTIC_GROUPS, TACTIC_MITRE_IDS, label_to_tactic

EXPECTED_TACTICS = {
    "Impact", "Reconnaissance", "InitialAccess_CredentialAccess",
    "PrivilegeEscalation",
}


class TestCouverture:
    def test_39_types_d_attaque_couverts(self):
        """
        39 = les 22 types de KDDTrain+ plus les 17 du test set. Le nombre
        est vérifié plutôt que commenté : c'est lui qui a été le trou.
        """
        assert len(TACTIC_GROUPS) == 39

    def test_aucun_doublon_de_label(self):
        assert len(set(TACTIC_GROUPS)) == len(TACTIC_GROUPS)

    def test_les_quatre_tactiques_sont_representees(self):
        assert set(TACTIC_GROUPS.values()) == EXPECTED_TACTICS

    @pytest.mark.parametrize("label", sorted(TACTIC_GROUPS))
    def test_chaque_label_donne_une_tactique_connue(self, label):
        assert label_to_tactic(label) in EXPECTED_TACTICS


class TestTaxonomieNslKdd:
    """
    Vérifie que le regroupement suit bien la taxonomie standard
    DoS/Probe/R2L/U2R, sur un échantillon de labels dont la catégorie ne
    prête pas à discussion dans la littérature.
    """

    @pytest.mark.parametrize("label", ["neptune", "smurf", "teardrop", "pod",
                                        "back", "land", "apache2", "udpstorm"])
    def test_dos_vers_impact(self, label):
        assert label_to_tactic(label) == "Impact"

    @pytest.mark.parametrize("label", ["ipsweep", "nmap", "portsweep", "satan",
                                        "mscan", "saint"])
    def test_probe_vers_reconnaissance(self, label):
        assert label_to_tactic(label) == "Reconnaissance"

    @pytest.mark.parametrize("label", ["guess_passwd", "ftp_write", "imap",
                                        "phf", "warezmaster", "snmpguess"])
    def test_r2l_vers_initial_access(self, label):
        assert label_to_tactic(label) == "InitialAccess_CredentialAccess"

    @pytest.mark.parametrize("label", ["buffer_overflow", "loadmodule", "perl",
                                        "rootkit", "sqlattack"])
    def test_u2r_vers_privilege_escalation(self, label):
        assert label_to_tactic(label) == "PrivilegeEscalation"


class TestChoixAmbigusDocumentes:
    """
    Trois labels sont classés différemment selon les sources. Le projet a
    tranché explicitement (voir l'en-tête du module). Ces tests figent la
    décision : si quelqu'un la change, il devra le faire sciemment.
    """

    def test_worm_classe_impact(self):
        assert label_to_tactic("worm") == "Impact"

    @pytest.mark.parametrize("label", ["ps", "xterm"])
    def test_ps_et_xterm_classes_privilege_escalation(self, label):
        assert label_to_tactic(label) == "PrivilegeEscalation"


class TestLabelInconnu:
    def test_label_inconnu_retourne_unknown(self):
        """
        Repli explicite : "Unknown" est filtré en amont de
        l'entraînement. Retourner une tactique par défaut fabriquerait
        des étiquettes fausses au lieu d'écarter le cas.
        """
        assert label_to_tactic("type_qui_n_existe_pas") == "Unknown"

    @pytest.mark.parametrize("value", ["", "NEPTUNE", " neptune"])
    def test_la_correspondance_est_stricte(self, value):
        """
        Pas de normalisation implicite (casse, espaces) : un label mal
        formé doit ressortir comme inconnu, pas être deviné.
        """
        assert label_to_tactic(value) == "Unknown"


class TestIdentifiantsMitre:
    def test_chaque_tactique_a_un_identifiant(self):
        assert set(TACTIC_MITRE_IDS) == EXPECTED_TACTICS

    @pytest.mark.parametrize("tactic,expected", [
        ("Impact", "TA0040"),
        ("Reconnaissance", "TA0043"),
        ("PrivilegeEscalation", "TA0004"),
        ("InitialAccess_CredentialAccess", "TA0001/TA0006"),
    ])
    def test_identifiants_conformes_au_referentiel(self, tactic, expected):
        assert TACTIC_MITRE_IDS[tactic] == expected


def test_repartition_par_tactique():
    """
    Rend la distribution visible : un déséquilibre extrême entre
    tactiques explique une partie des écarts de F1 du classifieur, et
    doit rester constaté plutôt que découvert.
    """
    counts = Counter(TACTIC_GROUPS.values())
    assert sum(counts.values()) == 39
    for tactic in EXPECTED_TACTICS:
        assert counts[tactic] >= 6, f"{tactic} sous-représentée : {counts[tactic]}"
