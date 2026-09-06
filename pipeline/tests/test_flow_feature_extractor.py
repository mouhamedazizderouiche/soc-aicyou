"""
Tests de flow_feature_extractor.py — extraction des 12 features NetFlow
v1 depuis les enregistrements `event_type: flow` de Suricata.

Ce module survit à l'échec du transfert inter-domaine : cet échec porte
sur le modèle, entraîné sur un autre réseau, pas sur l'extracteur. Il
reste le prérequis de toute reprise, d'où l'intérêt de le verrouiller.

Les tests portent surtout sur les REJETS et les cas limites, car c'est là
que se joue l'honnêteté du module : un enregistrement qu'on ne sait pas
représenter fidèlement doit être écarté et compté, jamais rempli avec une
valeur inventée.
"""

import pandas as pd
import pytest

from flow_feature_extractor import (
    L7_PROTO_BY_APP_PROTO,
    NETFLOW_V1_COLUMNS,
    NETFLOW_V1_MODEL_COLUMNS,
    PROTOCOL_NUMBERS,
    ExtractionStats,
    FlowFeatureError,
    extract_flow_features,
    flow_record_to_features,
    validate_netflow_v1_schema,
)


def make_flow(**overrides) -> dict:
    """Flux TCP complet, conforme au format réel observé dans eve.json."""
    event = {
        "timestamp": "2026-08-31T23:47:01.000000+0000",
        "event_type": "flow",
        "src_ip": "192.168.1.225", "src_port": 18009,
        "dest_ip": "192.168.1.249", "dest_port": 8888,
        "proto": "TCP", "app_proto": "tls",
        "flow": {
            "pkts_toserver": 3, "pkts_toclient": 2,
            "bytes_toserver": 198, "bytes_toclient": 120,
            "start": "2026-08-31T23:47:00.000000+0000",
            "end": "2026-08-31T23:47:00.500000+0000",
            "state": "closed",
        },
        "tcp": {"tcp_flags": "1b"},
    }
    event.update(overrides)
    return event


class TestExtractionNominale:
    def test_les_douze_features_sont_produites(self):
        row = flow_record_to_features(make_flow())
        assert set(row) == set(NETFLOW_V1_COLUMNS)

    def test_valeurs_correctement_transposees(self):
        row = flow_record_to_features(make_flow())
        assert row["IPV4_SRC_ADDR"] == "192.168.1.225"
        assert row["L4_DST_PORT"] == 8888
        assert row["PROTOCOL"] == 6            # TCP, numéro IANA
        assert row["IN_BYTES"] == 198          # toserver
        assert row["OUT_BYTES"] == 120         # toclient
        assert row["IN_PKTS"] == 3
        assert row["OUT_PKTS"] == 2

    def test_drapeaux_tcp_convertis_depuis_l_hexadecimal(self):
        """Suricata écrit "1b" ; NetFlow attend l'entier 27."""
        assert flow_record_to_features(make_flow())["TCP_FLAGS"] == 27

    def test_syn_seul_du_scan(self):
        """La signature de scan mesurée sur le trafic réel : flags "02"."""
        row = flow_record_to_features(make_flow(tcp={"tcp_flags": "02"}))
        assert row["TCP_FLAGS"] == 2

    def test_duree_calculee_en_millisecondes(self):
        assert flow_record_to_features(make_flow())["FLOW_DURATION_MILLISECONDS"] == 500

    def test_duree_nulle_acceptee(self):
        """Un flux d'un seul paquet a une durée nulle : c'est valide."""
        flow = make_flow()
        flow["flow"]["end"] = flow["flow"]["start"]
        assert flow_record_to_features(flow)["FLOW_DURATION_MILLISECONDS"] == 0

    def test_correspondance_l7_appliquee(self):
        assert flow_record_to_features(make_flow())["L7_PROTO"] == L7_PROTO_BY_APP_PROTO["tls"]


class TestCasLimitesComblesVolontairement:
    def test_icmp_sans_ports_donne_zero(self):
        """
        0 n'est pas un port légal : il ne peut pas être confondu avec une
        valeur réelle, et c'est la convention du jeu d'entraînement.
        """
        flow = make_flow(proto="ICMP", app_proto=None)
        flow.pop("src_port"); flow.pop("dest_port"); flow.pop("tcp")
        row = flow_record_to_features(flow)
        assert row["L4_SRC_PORT"] == 0 and row["L4_DST_PORT"] == 0
        assert row["PROTOCOL"] == 1

    def test_udp_sans_bloc_tcp_donne_flags_zero(self):
        """0 signifie « aucun drapeau TCP observé », ce qui est vrai."""
        flow = make_flow(proto="UDP", app_proto="dns")
        flow.pop("tcp")
        assert flow_record_to_features(flow)["TCP_FLAGS"] == 0

    @pytest.mark.parametrize("app_proto", ["failed", None, "quic", "ftp", "dhcp"])
    def test_app_proto_non_derive_tombe_sur_zero(self, app_proto):
        """
        0 est la valeur que nDPI lui-même utilise pour « non identifié ».
        Pour ftp et dhcp c'est même EXACTEMENT ce que contient le jeu
        d'entraînement — les mapper autrement créerait un écart.
        """
        assert flow_record_to_features(make_flow(app_proto=app_proto))["L7_PROTO"] == 0.0


class TestRejetsComptabilises:
    @pytest.mark.parametrize("overrides,motif", [
        ({"src_ip": "fe80::1", "dest_ip": "ff02::fb"}, "non-IPv4"),
        ({"proto": "PROTO-INCONNU"}, "protocole"),
        ({"event_type": "alert"}, "event_type"),
    ])
    def test_enregistrement_non_representable_rejete(self, overrides, motif):
        stats = ExtractionStats()
        assert flow_record_to_features(make_flow(**overrides), stats) is None
        assert sum(stats.rejected.values()) == 1
        assert any(motif in reason for reason in stats.rejected)

    def test_ipv6_rejete_et_non_converti(self):
        """
        Le schéma v1 déclare IPV4_SRC_ADDR et le jeu d'entraînement ne
        contient que de l'IPv4. Convertir serait inventer.
        """
        stats = ExtractionStats()
        flow = make_flow(src_ip="fe80::1", dest_ip="ff02::fb")
        assert flow_record_to_features(flow, stats) is None

    def test_compteur_manquant_rejete(self):
        stats = ExtractionStats()
        flow = make_flow()
        del flow["flow"]["bytes_toserver"]
        assert flow_record_to_features(flow, stats) is None

    def test_duree_negative_rejetee(self):
        stats = ExtractionStats()
        flow = make_flow()
        flow["flow"]["end"] = "2026-08-31T23:46:00.000000+0000"  # avant start
        assert flow_record_to_features(flow, stats) is None
        assert any("négative" in r for r in stats.rejected)

    def test_drapeaux_non_hexadecimaux_rejetes(self):
        stats = ExtractionStats()
        assert flow_record_to_features(make_flow(tcp={"tcp_flags": "zz"}), stats) is None

    def test_les_motifs_de_rejet_apparaissent_dans_le_resume(self):
        stats = ExtractionStats()
        stats.seen = 2
        flow_record_to_features(make_flow(src_ip="fe80::1", dest_ip="ff02::fb"), stats)
        summary = stats.summary()
        assert "rejetés" in summary and "IPv4" in summary


class TestContratDeSchema:
    def test_dataframe_produit_respecte_le_contrat(self):
        df, stats = extract_flow_features([make_flow(), make_flow()])
        assert list(df.columns) == NETFLOW_V1_COLUMNS
        assert len(df) == 2 and stats.accepted == 2

    def test_lot_vide_produit_un_dataframe_conforme(self):
        """Un lot sans flux exploitable ne doit pas casser le contrat."""
        df, _ = extract_flow_features([])
        assert list(df.columns) == NETFLOW_V1_COLUMNS and df.empty

    def test_les_adresses_ip_sont_exclues_de_l_entree_modele(self):
        """
        Les IP sont propres au plan d'adressage du banc d'essai : un
        modèle qui les utilise mémorise ce réseau au lieu d'apprendre un
        comportement.
        """
        assert "IPV4_SRC_ADDR" not in NETFLOW_V1_MODEL_COLUMNS
        assert "IPV4_DST_ADDR" not in NETFLOW_V1_MODEL_COLUMNS
        assert len(NETFLOW_V1_MODEL_COLUMNS) == 10

    def test_schema_etranger_rejete(self):
        with pytest.raises(FlowFeatureError):
            validate_netflow_v1_schema(pd.DataFrame({"autre": [1]}), context="test")

    def test_colonne_manquante_nommee_dans_l_erreur(self):
        df, _ = extract_flow_features([make_flow()])
        with pytest.raises(FlowFeatureError) as exc:
            validate_netflow_v1_schema(df.drop(columns=["TCP_FLAGS"]), context="test")
        assert "TCP_FLAGS" in str(exc.value)

    def test_validation_entree_modele(self):
        df, _ = extract_flow_features([make_flow()])
        validate_netflow_v1_schema(df[NETFLOW_V1_MODEL_COLUMNS],
                                    context="test", model_input=True)


def test_numeros_de_protocole_conformes_a_l_iana():
    assert PROTOCOL_NUMBERS["ICMP"] == 1
    assert PROTOCOL_NUMBERS["TCP"] == 6
    assert PROTOCOL_NUMBERS["UDP"] == 17
    assert PROTOCOL_NUMBERS["IPv6-ICMP"] == 58


def test_le_schema_compte_douze_features():
    assert len(NETFLOW_V1_COLUMNS) == 12
