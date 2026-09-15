"""
Tests du branchement modèle-local -> alertes live (live_flow_scoring).

Portent sur l'adaptateur alerte->flux et sur la LOGIQUE DE REPLI, sans
dépendre de l'indexeur ni des modèles entraînés (repli testé avec base_dir
vide ; scoring réel couvert par la démo sur alertes réelles).
"""

import pandas as pd
import pytest

from feature_schema import LOCAL_FLOW_FEATURE_COLUMNS
from live_flow_scoring import alert_to_netflow_row, level_to_band, score_alerts


def _alert_with_flow(**flow_over):
    flow = {
        "bytes_toserver": "6278", "bytes_toclient": "0",
        "pkts_toserver": "73", "pkts_toclient": "0",
        "src_port": "57621", "dest_port": "57621",
    }
    flow.update(flow_over)
    return {"data": {"proto": "UDP", "app_proto": "failed",
                     "src_port": "57621", "dest_port": "57621", "flow": flow}}


class TestAdaptateurAlerteVersFlux:
    def test_construit_les_dix_colonnes(self):
        row = alert_to_netflow_row(_alert_with_flow())
        assert set(row) == set(LOCAL_FLOW_FEATURE_COLUMNS)

    def test_coercition_des_chaines_en_entiers(self):
        row = alert_to_netflow_row(_alert_with_flow())
        assert row["IN_BYTES"] == 6278 and row["IN_PKTS"] == 73
        assert isinstance(row["IN_BYTES"], int)

    def test_protocole_traduit_en_numero(self):
        row = alert_to_netflow_row(_alert_with_flow())
        assert row["PROTOCOL"] == 17  # UDP

    def test_tcp_flags_absent_vaut_zero(self):
        """Limite documentée : les alertes indexées ne portent pas tcp_flags."""
        assert alert_to_netflow_row(_alert_with_flow())["TCP_FLAGS"] == 0

    def test_duree_sans_end_vaut_zero(self):
        """flow.end est absent des alertes indexées -> durée 0."""
        assert alert_to_netflow_row(_alert_with_flow(start="2026-09-13T13:08:39+0000"))["FLOW_DURATION_MILLISECONDS"] == 0

    def test_duree_calculee_si_start_et_end(self):
        row = alert_to_netflow_row(_alert_with_flow(
            start="2026-09-13T13:08:39.000000+0000", end="2026-09-13T13:08:39.500000+0000"))
        assert row["FLOW_DURATION_MILLISECONDS"] == 500

    def test_alerte_sans_flow_donne_none(self):
        assert alert_to_netflow_row({"data": {"proto": "TCP"}}) is None

    def test_alerte_sans_data_donne_none(self):
        assert alert_to_netflow_row({"rule": {"level": 5}}) is None

    def test_protocole_inconnu_donne_none(self):
        assert alert_to_netflow_row(_alert_with_flow() | {"data": {"proto": "MYSTERY", "flow": _alert_with_flow()["data"]["flow"]}}) is None


class TestRepli:
    def test_modele_absent_repli_integral(self):
        """base_dir sans modèle -> toutes les lignes en repli level_to_band."""
        df = pd.DataFrame({"rule_level": [3, 8, 13], "raw": [{}, {}, {}]})
        r = score_alerts(df, base_dir="/tmp/_no_model_here_")
        assert r["meta"]["method"] == "fallback"
        assert list(r["band_source"]) == ["fallback", "fallback", "fallback"]
        assert list(r["risk_band"]) == ["low", "high", "critical"]

    def test_repli_respecte_les_seuils_de_niveau(self):
        assert level_to_band(3) == "low"
        assert level_to_band(6) == "medium"
        assert level_to_band(9) == "high"
        assert level_to_band(14) == "critical"
