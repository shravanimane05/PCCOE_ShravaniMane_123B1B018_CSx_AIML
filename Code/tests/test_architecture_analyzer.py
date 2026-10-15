"""Pytest suite for ArchitectureAnalyzer."""

import pytest
from autotara.architecture_analyzer import ArchitectureAnalyzer, AttackSurfaceContext
from autotara.data_loader import DataLoader


@pytest.fixture
def analyzer_v1():
    return ArchitectureAnalyzer.from_loader(version="v1")


@pytest.fixture
def analyzer_v2():
    return ArchitectureAnalyzer.from_loader(version="v2")


def test_topology_summary_v1(analyzer_v1):
    """Verify baseline v1 topology counts."""
    summary = analyzer_v1.summarize_topology()
    assert summary["version"] == "1.0"
    assert summary["component_count"] == 9
    assert summary["interface_count"] == 10
    assert summary["data_flow_count"] == 10
    assert summary["trust_zone_count"] == 5
    assert summary["trust_boundary_count"] == 4
    assert summary["asset_count"] == 10
    assert "TB-05" not in summary["trust_boundary_ids"]


def test_topology_summary_v2(analyzer_v2):
    """Verify baseline v2 topology counts includes COMP-10, IF-11, TB-05."""
    summary = analyzer_v2.summarize_topology()
    assert summary["version"] == "2.0"
    assert summary["component_count"] == 10
    assert summary["interface_count"] == 11
    assert summary["trust_boundary_count"] == 5
    assert "TB-05" in summary["trust_boundary_ids"]


def test_derive_attack_surface_a01(analyzer_v1):
    """Verify attack surface derivation for A-01 (User Account / Access Token)."""
    surface = analyzer_v1.derive_attack_surface("A-01")
    assert surface.asset_id == "A-01"
    assert surface.asset_type == "mobile_app"
    assert surface.asset_category == "data"
    assert "COMP-01" in surface.hosted_components
    assert "COMP-02" in surface.hosted_components
    assert "TB-01" in surface.trust_boundary_ids
    assert "HTTPS/REST" in surface.protocols

    query = surface.build_query()
    assert "Asset: User Account and Mobile-App Access Token" in query
    assert "Type: mobile_app" in query
    assert "Trust Boundaries: TB-01" in query
    # Rule 1: Never include the pattern 'keywords' field in a query
    assert "keywords" not in query.lower()


def test_derive_attack_surface_a03(analyzer_v1):
    """Verify attack surface derivation for A-03 (OTA Firmware Package)."""
    surface = analyzer_v1.derive_attack_surface("A-03")
    assert surface.asset_id == "A-03"
    assert surface.asset_type == "ota_firmware"
    assert "TB-02" in surface.trust_boundary_ids
    query = surface.build_query()
    assert "Asset: OTA Firmware Package" in query
    assert "TB-02" in query
