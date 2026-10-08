from leanmesh_host.bridge.diag import diagnostics


def test_issue19_power_readback_is_reported_and_absence_stays_unknown():
    raw = {"validity": 32, "driver": {"tx_power_qdbm": 34}, "sdk": {}, "app": {}, "features": []}
    result = diagnostics(raw)
    assert result["driver"]["tx_power_qdbm"] == 34
    assert "driver.tx_power_qdbm" not in result["unknown"]
    raw["driver"] = {}
    result = diagnostics(raw)
    assert "tx_power_qdbm" not in result["driver"]
    assert "driver.tx_power_qdbm" in result["unknown"]
