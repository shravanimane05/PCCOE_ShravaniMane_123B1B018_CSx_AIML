"""Pytest suite for AutoTARA AI Phase 1 data loaders and cross-reference validation.

Verifies:
- All datasets load without error
- Zero broken links (threat -> control, req -> control, test -> req)
- Reverse links derived correctly from single source of truth
- Freshness status distribution (~15 Current, 10 Review Due, 5 Outdated)
- Trust boundary ID formats (TB-xx)
- Baseline v1 vs v2 diff contract (only COMP-10, IF-11, TB-05 added)
- Assets A-01 to A-10 match case study specifications
- DataValidator reports zero broken links
"""

from datetime import datetime
import re
from pathlib import Path
import pytest

from autotara.config import get_config
from autotara.data_loader import DataLoader, compute_freshness_status
from autotara.validation import DataValidator


@pytest.fixture
def loader():
    return DataLoader()


@pytest.fixture
def config():
    return get_config()


def test_config_loads_properly(config):
    """Verify config.yaml is parsed with required parameters."""
    assert config.project_name == "AutoTARA AI"
    assert config.reference_date == datetime.strptime("2026-10-13", "%Y-%m-%d")
    rules = config.freshness_rules
    assert rules["current_ahead_days"] == 30
    assert rules["outdated_overdue_days"] == 180


def test_datasets_exist_and_load(loader):
    """Verify all knowledge base and architecture files load successfully."""
    kb = loader.load_all_knowledge_base()
    assert len(kb["threat_patterns"]) >= 30
    assert len(kb["controls"]) >= 30
    assert len(kb["requirements"]) >= 30
    assert len(kb["verification_tests"]) >= 30
    assert "impact_scale" in kb["rubric"]
    assert "attack_feasibility_scale" in kb["rubric"]
    assert "risk_bands" in kb["rubric"]


def test_suggested_control_ids_exist_in_controls(loader):
    """Verify every suggested_control_ids entry in threat_patterns exists in controls.json."""
    tp = loader.load_threat_patterns()
    ctrl = loader.load_controls()
    ctrl_ids = {c["id"] for c in ctrl}

    broken_links = []
    for t in tp:
        for cid in t.get("suggested_control_ids", []):
            if cid not in ctrl_ids:
                broken_links.append((t["id"], cid))

    assert broken_links == [], f"Found broken control links in threat patterns: {broken_links}"


def test_every_control_has_at_least_one_requirement(loader):
    """Verify every control has at least one requirement pointing to it (derived reverse link)."""
    tp = loader.load_threat_patterns()
    ctrl = loader.load_controls()
    req = loader.load_requirements()
    tests = loader.load_verification_tests()

    derived = loader.build_derived_traceability(tp, ctrl, req, tests)
    c_to_r = derived["control_to_requirements"]

    controls_without_req = [cid for cid, r_list in c_to_r.items() if len(r_list) == 0]
    assert controls_without_req == [], f"Controls lacking requirements: {controls_without_req}"


def test_every_requirement_has_at_least_one_test(loader):
    """Verify every requirement has at least one verification test pointing to it."""
    tp = loader.load_threat_patterns()
    ctrl = loader.load_controls()
    req = loader.load_requirements()
    tests = loader.load_verification_tests()

    derived = loader.build_derived_traceability(tp, ctrl, req, tests)
    r_to_t = derived["requirement_to_tests"]

    reqs_without_test = [rid for rid, t_list in r_to_t.items() if len(t_list) == 0]
    assert reqs_without_test == [], f"Requirements lacking verification tests: {reqs_without_test}"


def test_threat_patterns_trust_boundary_id_format(loader):
    """Verify trust_boundary in threat_patterns holds IDs like TB-01, not free-text."""
    tp = loader.load_threat_patterns()
    tb_pattern = re.compile(r"^TB-\d{2}$")

    for t in tp:
        tb = t.get("trust_boundary")
        assert tb is not None, f"Threat pattern {t['id']} missing trust_boundary"
        assert tb_pattern.match(tb), (
            f"Threat pattern {t['id']} has invalid trust_boundary '{tb}'. Must match TB-xx format."
        )


def test_freshness_status_counts(loader, config):
    """Verify freshness rule produces roughly 15 Current, 10 Review Due, 5 Outdated."""
    tp = loader.load_threat_patterns(annotate_freshness=True)
    counts = {"Current": 0, "Review Due": 0, "Outdated": 0}

    for t in tp:
        status = t["freshness_status"]
        assert status in counts, f"Unexpected freshness status: {status}"
        counts[status] += 1

    # Exactly 15, 10, 5 configured
    assert counts["Current"] == 15, f"Expected 15 Current, got {counts['Current']}"
    assert counts["Review Due"] == 10, f"Expected 10 Review Due, got {counts['Review Due']}"
    assert counts["Outdated"] == 5, f"Expected 5 Outdated, got {counts['Outdated']}"


def test_freshness_boundary_conditions(config):
    """Verify edge boundary conditions: +31, +30, 0, -180, and -181 days."""
    from datetime import timedelta
    ref = config.reference_date

    # +31 days -> Current
    d_current = (ref + timedelta(days=31)).strftime("%Y-%m-%d")
    assert compute_freshness_status(d_current, ref) == "Current"

    # +30 days -> Review Due (boundary)
    d_edge_ahead = (ref + timedelta(days=30)).strftime("%Y-%m-%d")
    assert compute_freshness_status(d_edge_ahead, ref) == "Review Due"

    # 0 days (today) -> Review Due
    d_today = ref.strftime("%Y-%m-%d")
    assert compute_freshness_status(d_today, ref) == "Review Due"

    # Exactly 180 days overdue (-180 days) -> Review Due (inclusive boundary)
    d_edge_overdue = (ref - timedelta(days=180)).strftime("%Y-%m-%d")
    assert compute_freshness_status(d_edge_overdue, ref) == "Review Due"

    # 181 days overdue (-181 days) -> Outdated (>180 days overdue)
    d_outdated = (ref - timedelta(days=181)).strftime("%Y-%m-%d")
    assert compute_freshness_status(d_outdated, ref) == "Outdated"


def test_baseline_v2_diff_only_comp10_if11_tb05(loader):
    """Verify baseline v2 contains ONLY COMP-10, IF-11, and TB-05 additions relative to v1."""
    v1 = loader.load_architecture("v1")
    v2 = loader.load_architecture("v2")

    # Components
    v1_comps = {c["id"] for c in v1["components"]}
    v2_comps = {c["id"] for c in v2["components"]}
    assert v2_comps - v1_comps == {"COMP-10"}, f"Unexpected component additions in v2: {v2_comps - v1_comps}"
    assert v1_comps - v2_comps == set(), "Components were removed in v2"

    # Interfaces
    v1_ifs = {i["id"] for i in v1["interfaces"]}
    v2_ifs = {i["id"] for i in v2["interfaces"]}
    assert v2_ifs - v1_ifs == {"IF-11"}, f"Unexpected interface additions in v2: {v2_ifs - v1_ifs}"
    assert v1_ifs - v2_ifs == set(), "Interfaces were removed in v2"

    # Trust boundaries
    v1_tbs = {t["id"] for t in v1["trust_boundaries"]}
    v2_tbs = {t["id"] for t in v2["trust_boundaries"]}
    assert v2_tbs - v1_tbs == {"TB-05"}, f"Unexpected trust boundary additions in v2: {v2_tbs - v1_tbs}"
    assert v1_tbs - v2_tbs == set(), "Trust boundaries were removed in v2"

    # Data flows, trust zones, assets should be identical
    v1_dfs = {d["id"] for d in v1["data_flows"]}
    v2_dfs = {d["id"] for d in v2["data_flows"]}
    assert v1_dfs == v2_dfs, "Data flows differ between v1 and v2"

    v1_assets = {a["id"] for a in v1["assets"]}
    v2_assets = {a["id"] for a in v2["assets"]}
    assert v1_assets == v2_assets, "Assets differ between v1 and v2"


def test_assets_a01_to_a10_match_case_study(loader):
    """Verify assets A-01 to A-10 match the case study exactly with valid categories."""
    v1 = loader.load_architecture("v1")
    assets = {a["id"]: a for a in v1["assets"]}

    expected_assets = {
        "A-01": ("User Account and Mobile-App Access Token", "data"),
        "A-02": ("Cloud Backend API", "component"),
        "A-03": ("OTA Firmware Package", "data"),
        "A-04": ("Firmware Signing Key and Certificate", "data"),
        "A-05": ("Telematics Control Unit (TCU)", "component"),
        "A-06": ("Central Gateway ECU", "component"),
        "A-07": ("CAN/Ethernet Messages and Vehicle Commands", "data"),
        "A-08": ("Diagnostic Services and Session Access", "component"),
        "A-09": ("Vehicle Telemetry and Location Data", "data"),
        "A-10": ("Security and Audit Logs", "data"),
    }

    assert len(assets) == 10
    for aid, (expected_name, expected_category) in expected_assets.items():
        assert aid in assets, f"Missing asset {aid}"
        assert assets[aid]["name"] == expected_name, (
            f"Asset {aid} name mismatch: expected '{expected_name}', got '{assets[aid]['name']}'"
        )
        assert assets[aid]["category"] == expected_category, (
            f"Asset {aid} category mismatch: expected '{expected_category}', got '{assets[aid]['category']}'"
        )


def test_validator_reports_zero_broken_links():
    """Verify DataValidator reports valid status with zero errors."""
    validator = DataValidator()
    report = validator.validate_all()
    assert report.is_valid is True, f"Validation failed with errors: {report.errors}"
    assert len(report.errors) == 0
