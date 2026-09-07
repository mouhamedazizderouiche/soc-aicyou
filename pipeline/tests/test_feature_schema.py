"""
Tests de feature_schema.py — le garde-fou qui empêche un modèle
NSL-KDD de recevoir des features d'un autre schéma.

Ce module a une valeur particulière : il transforme en erreur explicite
un cas qui, sinon, produirait soit un crash cryptique de XGBoost, soit
-- plus grave -- une prédiction silencieuse et dénuée de sens si le
nombre de colonnes coïncidait par hasard. Les tests couvrent donc autant
le REJET que la qualité du diagnostic, car c'est le diagnostic qui fait
la valeur du module.
"""

import pandas as pd
import pytest

from feature_schema import (
    LIVE_PIPELINE_FEATURE_COLUMNS,
    NSL_KDD_FEATURE_COLUMNS,
    FeatureSchemaError,
    validate_nsl_kdd_schema,
)


def make_nsl_kdd_frame(n_rows: int = 3) -> pd.DataFrame:
    """DataFrame conforme au schéma NSL-KDD, valeurs arbitraires."""
    return pd.DataFrame(
        {col: [0] * n_rows for col in NSL_KDD_FEATURE_COLUMNS},
        columns=NSL_KDD_FEATURE_COLUMNS,
    )


def make_live_frame(n_rows: int = 3) -> pd.DataFrame:
    """DataFrame au schéma du pipeline live (feature_extractor.py)."""
    return pd.DataFrame(
        {col: [0] * n_rows for col in LIVE_PIPELINE_FEATURE_COLUMNS},
        columns=LIVE_PIPELINE_FEATURE_COLUMNS,
    )


class TestSchemaValide:
    def test_schema_nsl_kdd_accepte(self):
        """Le cas nominal ne doit rien lever."""
        validate_nsl_kdd_schema(make_nsl_kdd_frame(), context="test")

    def test_dataframe_vide_mais_colonnes_correctes_accepte(self):
        """
        Zéro ligne n'est pas une erreur de schéma : un lot vide est un
        cas de fonctionnement normal du pipeline, pas une anomalie.
        """
        validate_nsl_kdd_schema(make_nsl_kdd_frame(n_rows=0), context="test")

    def test_ordre_des_colonnes_indifferent(self):
        """
        La validation porte sur l'ENSEMBLE des colonnes. XGBoost réaligne
        sur les noms, donc imposer l'ordre rejetterait des entrées
        parfaitement exploitables.
        """
        df = make_nsl_kdd_frame()
        validate_nsl_kdd_schema(df[list(reversed(NSL_KDD_FEATURE_COLUMNS))],
                                 context="test")


class TestSchemaLiveRejete:
    def test_schema_live_leve_une_erreur(self):
        with pytest.raises(FeatureSchemaError):
            validate_nsl_kdd_schema(make_live_frame(), context="test")

    def test_le_message_identifie_le_cas_live(self):
        """
        Le message doit nommer l'écart architectural connu, pas se
        contenter d'un « colonnes invalides » générique : c'est ce qui
        évite de rechercher un bug local là où il n'y en a pas.
        """
        with pytest.raises(FeatureSchemaError) as exc:
            validate_nsl_kdd_schema(make_live_frame(), context="test")
        message = str(exc.value)
        assert "feature_extractor" in message
        assert "journal-technique" in message

    def test_trois_colonnes_live_suffisent_a_la_detection(self):
        """
        L'heuristique de détection du cas live exige au moins 3 colonnes
        connues. Une sortie live tronquée doit rester diagnostiquée comme
        telle.
        """
        partial = make_live_frame()[LIVE_PIPELINE_FEATURE_COLUMNS[:3]]
        with pytest.raises(FeatureSchemaError) as exc:
            validate_nsl_kdd_schema(partial, context="test")
        assert "feature_extractor" in str(exc.value)


class TestDiagnostic:
    def test_colonne_manquante_est_nommee(self):
        df = make_nsl_kdd_frame().drop(columns=["duration"])
        with pytest.raises(FeatureSchemaError) as exc:
            validate_nsl_kdd_schema(df, context="test")
        assert "duration" in str(exc.value)

    def test_colonne_en_trop_est_nommee(self):
        df = make_nsl_kdd_frame()
        df["colonne_inattendue"] = 0
        with pytest.raises(FeatureSchemaError) as exc:
            validate_nsl_kdd_schema(df, context="test")
        assert "colonne_inattendue" in str(exc.value)

    def test_le_contexte_apparait_dans_le_message(self):
        """
        Le contexte identifie le point d'appel. Sans lui, une erreur
        remontée depuis un pipeline à plusieurs étages est bien plus
        longue à localiser.
        """
        with pytest.raises(FeatureSchemaError) as exc:
            validate_nsl_kdd_schema(make_live_frame(), context="RiskScorer.assess")
        assert "RiskScorer.assess" in str(exc.value)

    def test_bon_nombre_de_colonnes_mais_mauvais_noms_rejete(self):
        """
        Le cas le plus dangereux, et la raison d'être du module : 41
        colonnes de noms différents passeraient un simple contrôle de
        cardinalité et produiraient une prédiction silencieuse.
        """
        df = pd.DataFrame({f"col_{i}": [0] for i in range(len(NSL_KDD_FEATURE_COLUMNS))})
        with pytest.raises(FeatureSchemaError):
            validate_nsl_kdd_schema(df, context="test")


def test_le_schema_nsl_kdd_compte_41_colonnes():
    """Ancre le contrat : NSL-KDD a 41 features hors étiquette."""
    assert len(NSL_KDD_FEATURE_COLUMNS) == 41
    assert len(set(NSL_KDD_FEATURE_COLUMNS)) == 41, "doublon dans le schéma"


def test_aucun_recouvrement_entre_les_deux_schemas():
    """
    Fait central du projet, vérifié plutôt qu'affirmé : les deux espaces
    de features n'ont aucun nom en commun. C'est ce qui rend impossible
    toute conversion implicite de l'un vers l'autre.
    """
    assert set(NSL_KDD_FEATURE_COLUMNS) & set(LIVE_PIPELINE_FEATURE_COLUMNS) == set()


# --- Ajout 07/09/2026 : schéma des flux locaux (troisième schéma) -----------

from feature_schema import (  # noqa: E402
    LOCAL_FLOW_FEATURE_COLUMNS,
    identify_schema,
    validate_local_flow_schema,
    verify_local_flow_against_extractor,
)


def make_local_flow_frame(n_rows: int = 3) -> pd.DataFrame:
    return pd.DataFrame(
        {col: [0] * n_rows for col in LOCAL_FLOW_FEATURE_COLUMNS},
        columns=LOCAL_FLOW_FEATURE_COLUMNS,
    )


class TestSchemaFluxLocaux:
    def test_schema_flux_local_valide_accepte(self):
        validate_local_flow_schema(make_local_flow_frame(), context="test")

    def test_dix_colonnes_ip_exclues(self):
        """Les adresses IP ne doivent JAMAIS être dans l'entrée modèle."""
        assert len(LOCAL_FLOW_FEATURE_COLUMNS) == 10
        assert "IPV4_SRC_ADDR" not in LOCAL_FLOW_FEATURE_COLUMNS
        assert "IPV4_DST_ADDR" not in LOCAL_FLOW_FEATURE_COLUMNS

    def test_reste_aligne_sur_l_extracteur(self):
        assert verify_local_flow_against_extractor() is True

    def test_nsl_kdd_fourni_est_rejete_et_identifie(self):
        with pytest.raises(FeatureSchemaError) as exc:
            validate_local_flow_schema(make_nsl_kdd_frame(), context="test")
        assert "NSL-KDD" in str(exc.value)

    def test_agregats_fournis_sont_rejetes_et_identifies(self):
        with pytest.raises(FeatureSchemaError) as exc:
            validate_local_flow_schema(make_live_frame(), context="test")
        assert "agrégats d'alertes" in str(exc.value)


class TestIdentificationDesTroisSchemas:
    def test_identifie_local_flow(self):
        assert identify_schema(make_local_flow_frame()) == "local_flow"

    def test_identifie_nsl_kdd(self):
        assert identify_schema(make_nsl_kdd_frame()) == "nsl_kdd"

    def test_identifie_agregats(self):
        assert identify_schema(make_live_frame()) == "alert_aggregate"

    def test_schema_etranger_est_inconnu(self):
        frame = pd.DataFrame({"a": [1], "b": [2]})
        assert identify_schema(frame) == "inconnu"
