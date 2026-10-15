"""Pytest suite for MitigationEngine."""

import pytest
from autotara.mitigation_engine import MitigationEngine


@pytest.fixture
def mitigation_engine():
    return MitigationEngine()


def test_mitigation_bundle_generation(mitigation_engine):
    """Verify mitigation bundle drafts controls, requirements, and tests for TP-001."""
    bundle = mitigation_engine.draft_mitigation_bundle("TP-001", asset_name="Mobile Access Token")
    assert bundle.threat_pattern_id == "TP-001"
    assert len(bundle.controls) > 0
    assert len(bundle.requirements) > 0

    ctrl_ids = [c["id"] for c in bundle.controls]
    assert "CTRL-002" in ctrl_ids

    # Verify template replacement
    for req in bundle.requirements:
        assert "{asset}" not in req.requirement_text
        assert "Mobile Access Token" in req.requirement_text
        assert len(req.tests) > 0


def test_mitigation_bundle_tp002(mitigation_engine):
    """Verify mitigation bundle drafts controls, requirements, and tests for TP-002."""
    bundle = mitigation_engine.draft_mitigation_bundle("TP-002", asset_name="OTA Firmware Image")
    assert bundle.threat_pattern_id == "TP-002"
    ctrl_ids = [c["id"] for c in bundle.controls]
    assert "CTRL-003" in ctrl_ids
    assert len(bundle.requirements) > 0
