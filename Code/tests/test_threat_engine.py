"""Pytest suite for ThreatEngine."""

import pytest
from autotara.threat_engine import ThreatEngine


@pytest.fixture
def threat_engine():
    return ThreatEngine()


def test_threat_engine_asset_identification(threat_engine):
    """Verify threat identification retrieves relevant threats for A-01 (User Account / Token)."""
    ident = threat_engine.identify_threats_for_asset("A-01", mode="hybrid", top_k=3)
    assert ident.asset_id == "A-01"
    assert ident.retrieval_mode == "hybrid"
    assert len(ident.results) > 0
    top_threat = ident.results[0]
    assert top_threat.pattern_id == "TP-001"
    assert top_threat.rank == 1


def test_threat_engine_asset_a03_identification(threat_engine):
    """Verify threat identification retrieves OTA threats (TP-024, TP-002) for A-03."""
    ident = threat_engine.identify_threats_for_asset("A-03", mode="hybrid", top_k=3)
    assert ident.asset_id == "A-03"
    assert len(ident.results) > 0
    top_pids = [r.pattern_id for r in ident.results]
    assert "TP-002" in top_pids
    assert "TP-024" in top_pids


def test_threat_engine_all_assets(threat_engine):
    """Verify threat identification across all 10 assets."""
    all_threats = threat_engine.identify_threats_for_all_assets(mode="bm25", top_k=2)
    assert len(all_threats) == 10
    for aid, ident in all_threats.items():
        assert len(ident.results) > 0
