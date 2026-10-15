"""Cross-reference and schema validator for AutoTARA AI data artifacts.

Enforces zero broken links, single-source-of-truth reverse derivation,
trust boundary ID formats, and baseline v1/v2 change contracts.
"""

from dataclasses import dataclass, field
from datetime import datetime
import sys
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set

# Support running as a standalone script or as a module
code_dir = Path(__file__).resolve().parent.parent
if str(code_dir) not in sys.path:
    sys.path.insert(0, str(code_dir))

from autotara.config import get_config
from autotara.data_loader import DataLoader, compute_freshness_status


@dataclass
class ValidationReport:
    is_valid: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    def add_error(self, message: str) -> None:
        self.errors.append(message)
        self.is_valid = False

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)


class DataValidator:
    """Validates AutoTARA AI datasets for consistency, completeness, and integrity."""

    def __init__(self, root_dir: Optional[Path] = None):
        self.loader = DataLoader(root_dir=root_dir)
        self.config = get_config(root_dir=root_dir)

    def validate_all(self) -> ValidationReport:
        """Run all Phase 1 validation checks and return a unified report."""
        report = ValidationReport()

        try:
            v1 = self.loader.load_architecture("v1")
            v2 = self.loader.load_architecture("v2")
            tp = self.loader.load_threat_patterns(annotate_freshness=False)
            ctrl = self.loader.load_controls()
            req = self.loader.load_requirements()
            test = self.loader.load_verification_tests()
            rubric = self.loader.load_rubric()
        except Exception as e:
            report.add_error(f"Failed to load dataset files: {e}")
            return report

        # 1. ID Uniqueness
        self._check_id_uniqueness("threat_patterns", [t["id"] for t in tp], report)
        self._check_id_uniqueness("controls", [c["id"] for c in ctrl], report)
        self._check_id_uniqueness("requirements", [r["id"] for r in req], report)
        self._check_id_uniqueness("verification_tests", [t["id"] for t in test], report)
        self._check_id_uniqueness("baseline_v1_components", [c["id"] for c in v1.get("components", [])], report)
        self._check_id_uniqueness("baseline_v1_interfaces", [i["id"] for i in v1.get("interfaces", [])], report)
        self._check_id_uniqueness("baseline_v1_assets", [a["id"] for a in v1.get("assets", [])], report)

        # 2. Suggested Control IDs in threat_patterns exist in controls.json
        ctrl_ids = {c["id"] for c in ctrl}
        broken_links = 0
        for t in tp:
            for cid in t.get("suggested_control_ids", []):
                if cid not in ctrl_ids:
                    broken_links += 1
                    report.add_error(f"Threat pattern {t['id']} references missing control {cid}")

        # 3. Every control has >= 1 requirement
        derived = self.loader.build_derived_traceability(tp, ctrl, req, test)
        ctrl_to_req = derived["control_to_requirements"]
        controls_without_req = [cid for cid in ctrl_ids if not ctrl_to_req.get(cid)]
        for cid in controls_without_req:
            report.add_error(f"Control {cid} has no linked requirements in requirements.json")

        # 4. Every requirement has >= 1 verification test
        req_ids = {r["id"] for r in req}
        req_to_test = derived["requirement_to_tests"]
        reqs_without_test = [rid for rid in req_ids if not req_to_test.get(rid)]
        for rid in reqs_without_test:
            report.add_error(f"Requirement {rid} has no linked verification tests in verification_tests.json")

        # 5. Check all forward links in requirements point to existing controls
        for r in req:
            for cid in r.get("linked_control_ids", []):
                if cid not in ctrl_ids:
                    broken_links += 1
                    report.add_error(f"Requirement {r['id']} references unknown control {cid}")

        # 6. Check all forward links in verification tests point to existing requirements
        for t in test:
            for rid in t.get("linked_requirement_ids", []):
                if rid not in req_ids:
                    broken_links += 1
                    report.add_error(f"Test {t['id']} references unknown requirement {rid}")

        report.stats["broken_link_count"] = broken_links
        report.stats["controls_without_requirements_count"] = len(controls_without_req)
        report.stats["requirements_without_tests_count"] = len(reqs_without_test)

        # 7. Trust boundary format in threat_patterns: must match TB-xx ID format
        tb_id_regex = re.compile(r"^TB-\d{2}$")
        for t in tp:
            tb_val = t.get("trust_boundary")
            if not tb_val:
                report.add_error(f"Threat pattern {t['id']} missing trust_boundary")
            elif not tb_id_regex.match(tb_val):
                report.add_error(
                    f"Threat pattern {t['id']} trust_boundary '{tb_val}' is not a valid TB ID (e.g. TB-01)"
                )

        # 8. Check Freshness status distribution
        ref_date = self.config.reference_date
        c_days = self.config.freshness_rules["current_ahead_days"]
        o_days = self.config.freshness_rules["outdated_overdue_days"]
        counts = {"Current": 0, "Review Due": 0, "Outdated": 0}
        for t in tp:
            nrd = t.get("next_review_date")
            if not nrd:
                report.add_error(f"Threat pattern {t['id']} missing next_review_date")
                continue
            status = compute_freshness_status(nrd, ref_date, c_days, o_days)
            counts[status] = counts.get(status, 0) + 1

        report.stats["freshness_counts"] = counts
        if counts["Current"] == len(tp):
            report.add_error("All threat patterns computed as 'Current'; date generation rule is incorrect")
        if counts["Outdated"] == 0:
            report.add_warning("Zero threat patterns computed as 'Outdated'")

        # 9. Assets A-01 to A-10 verification
        expected_assets = {f"A-{i:02d}" for i in range(1, 11)}
        actual_assets = {a["id"]: a for a in v1.get("assets", [])}
        if set(actual_assets.keys()) != expected_assets:
            report.add_error(
                f"Baseline v1 assets mismatch. Expected {sorted(expected_assets)}, got {sorted(actual_assets.keys())}"
            )

        for aid, a in actual_assets.items():
            cat = a.get("category")
            if cat not in ("data", "component"):
                report.add_error(f"Asset {aid} has invalid category '{cat}'; must be 'data' or 'component'")

        # 10. Baseline v1 vs Baseline v2 diff contract
        v1_c = {c["id"] for c in v1.get("components", [])}
        v2_c = {c["id"] for c in v2.get("components", [])}
        added_c = v2_c - v1_c
        removed_c = v1_c - v2_c

        v1_i = {i["id"] for i in v1.get("interfaces", [])}
        v2_i = {i["id"] for i in v2.get("interfaces", [])}
        added_i = v2_i - v1_i
        removed_i = v1_i - v2_i

        v1_tb = {tb["id"] for tb in v1.get("trust_boundaries", [])}
        v2_tb = {tb["id"] for tb in v2.get("trust_boundaries", [])}
        added_tb = v2_tb - v1_tb
        removed_tb = v1_tb - v2_tb

        if added_c != {"COMP-10"}:
            report.add_error(f"Baseline v2 component additions expected {{'COMP-10'}}, got {added_c}")
        if removed_c:
            report.add_error(f"Baseline v2 removed components unexpectedly: {removed_c}")

        if added_i != {"IF-11"}:
            report.add_error(f"Baseline v2 interface additions expected {{'IF-11'}}, got {added_i}")
        if removed_i:
            report.add_error(f"Baseline v2 removed interfaces unexpectedly: {removed_i}")

        if added_tb != {"TB-05"}:
            report.add_error(f"Baseline v2 trust boundary additions expected {{'TB-05'}}, got {added_tb}")
        if removed_tb:
            report.add_error(f"Baseline v2 removed trust boundaries unexpectedly: {removed_tb}")

        # Rubric checks
        if "impact_scale" not in rubric or len(rubric["impact_scale"]) != 5:
            report.add_error("prototype_rubric.json impact_scale must have 5 levels (1-5)")
        if "attack_feasibility_scale" not in rubric or len(rubric["attack_feasibility_scale"]) != 5:
            report.add_error("prototype_rubric.json attack_feasibility_scale must have 5 levels (1-5)")
        if "risk_bands" not in rubric or len(rubric["risk_bands"]) != 4:
            report.add_error("prototype_rubric.json risk_bands must have 4 bands")

        report.stats["total_threat_patterns"] = len(tp)
        report.stats["total_controls"] = len(ctrl)
        report.stats["total_requirements"] = len(req)
        report.stats["total_tests"] = len(test)

        return report

    def _check_id_uniqueness(self, collection_name: str, ids: List[str], report: ValidationReport) -> None:
        seen = set()
        duplicates = set()
        for item_id in ids:
            if item_id in seen:
                duplicates.add(item_id)
            seen.add(item_id)
        if duplicates:
            report.add_error(f"Duplicate IDs in {collection_name}: {sorted(duplicates)}")


def main() -> None:
    validator = DataValidator()
    report = validator.validate_all()
    print("=" * 60)
    print("AutoTARA AI — Phase 1 Data Validation")
    print("=" * 60)
    print(f"Status:                           {'PASS' if report.is_valid else 'FAIL'}")
    print(f"Broken Link Count:                {report.stats.get('broken_link_count', 0)}")
    print(f"Controls Without Requirements:    {report.stats.get('controls_without_requirements_count', 0)}")
    print(f"Requirements Without Tests:       {report.stats.get('requirements_without_tests_count', 0)}")
    print(f"Freshness Status Counts:          {report.stats.get('freshness_counts')}")
    print("-" * 60)
    print(f"Total Threat Patterns:            {report.stats.get('total_threat_patterns')}")
    print(f"Total Controls:                   {report.stats.get('total_controls')}")
    print(f"Total Requirements:               {report.stats.get('total_requirements')}")
    print(f"Total Tests:                      {report.stats.get('total_tests')}")
    print("-" * 60)
    if report.errors:
        print(f"Errors ({len(report.errors)}):")
        for err in report.errors:
            print(f"  [ERROR] {err}")
    else:
        print("Zero broken links / zero validation errors.")
    if report.warnings:
        print(f"Warnings ({len(report.warnings)}):")
        for warn in report.warnings:
            print(f"  [WARN]  {warn}")
    print("=" * 60)


if __name__ == "__main__":
    main()
