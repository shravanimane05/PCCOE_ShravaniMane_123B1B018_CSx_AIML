"""Data loading and normalization utilities for AutoTARA AI.

Loads architecture baselines, threat patterns, controls, requirements,
verification tests, and rubric definitions with schema validation and
computed/derived reverse references.
"""

from datetime import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from autotara.config import get_config


def compute_freshness_status(
    next_review_date_str: str,
    reference_date: datetime,
    current_ahead_days: int = 30,
    outdated_overdue_days: int = 180,
) -> str:
    """Compute the freshness status of a threat pattern using the single next_review_date rule.

    - Current: next_review_date > reference_date + current_ahead_days
    - Review Due: reference_date - outdated_overdue_days <= next_review_date <= reference_date + current_ahead_days
    - Outdated: next_review_date < reference_date - outdated_overdue_days
    """
    review_date = datetime.strptime(next_review_date_str, "%Y-%m-%d")
    days_ahead = (review_date - reference_date).days

    if days_ahead > current_ahead_days:
        return "Current"
    elif days_ahead >= -outdated_overdue_days:
        return "Review Due"
    else:
        return "Outdated"


class DataLoader:
    """Loader and indexer for AutoTARA AI datasets."""

    def __init__(self, root_dir: Optional[Path] = None):
        self.config = get_config(root_dir=root_dir)
        self.arch_dir = self.config.architecture_dir
        self.kb_dir = self.config.knowledge_base_dir
        self.ref_date = self.config.reference_date
        self.freshness_rules = self.config.freshness_rules

    def load_json(self, path: Path) -> Any:
        """Load JSON file with UTF-8 encoding."""
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def load_architecture(self, version: str = "v1") -> Dict[str, Any]:
        """Load architecture baseline (v1 or v2)."""
        filename = "baseline_v1.json" if version in ("v1", "1", "1.0") else "baseline_v2_bluetooth_adapter.json"
        return self.load_json(self.arch_dir / filename)

    def load_threat_patterns(self, annotate_freshness: bool = True) -> List[Dict[str, Any]]:
        """Load threat patterns, optionally annotating computed freshness status."""
        patterns = self.load_json(self.kb_dir / "threat_patterns.json")
        if annotate_freshness:
            c_days = self.freshness_rules["current_ahead_days"]
            o_days = self.freshness_rules["outdated_overdue_days"]
            for p in patterns:
                p["freshness_status"] = compute_freshness_status(
                    p["next_review_date"],
                    self.ref_date,
                    current_ahead_days=c_days,
                    outdated_overdue_days=o_days,
                )
        return patterns

    def load_controls(self) -> List[Dict[str, Any]]:
        """Load controls."""
        return self.load_json(self.kb_dir / "controls.json")

    def load_requirements(self) -> List[Dict[str, Any]]:
        """Load requirements."""
        return self.load_json(self.kb_dir / "requirements.json")

    def load_verification_tests(self) -> List[Dict[str, Any]]:
        """Load verification tests."""
        return self.load_json(self.kb_dir / "verification_tests.json")

    def load_rubric(self) -> Dict[str, Any]:
        """Load impact/feasibility scales and risk bands."""
        return self.load_json(self.kb_dir / "prototype_rubric.json")

    def load_all_knowledge_base(self) -> Dict[str, Any]:
        """Load all knowledge base components together."""
        return {
            "threat_patterns": self.load_threat_patterns(),
            "controls": self.load_controls(),
            "requirements": self.load_requirements(),
            "verification_tests": self.load_verification_tests(),
            "rubric": self.load_rubric(),
        }

    def build_derived_traceability(
        self,
        threat_patterns: Optional[List[Dict[str, Any]]] = None,
        controls: Optional[List[Dict[str, Any]]] = None,
        requirements: Optional[List[Dict[str, Any]]] = None,
        verification_tests: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Derive reverse links from single source of truth forward links:

        Forward links:
          threat_patterns.suggested_control_ids -> controls
          requirements.linked_control_ids -> controls
          verification_tests.linked_requirement_ids -> requirements

        Derived reverse links:
          control_to_requirements: {CTRL-xxx: [REQ-yyy, ...]}
          requirement_to_tests: {REQ-yyy: [TEST-zzz, ...]}
          control_to_threats: {CTRL-xxx: [TP-aaa, ...]}
        """
        tp = threat_patterns if threat_patterns is not None else self.load_threat_patterns()
        ctrl = controls if controls is not None else self.load_controls()
        req = requirements if requirements is not None else self.load_requirements()
        tests = verification_tests if verification_tests is not None else self.load_verification_tests()

        ctrl_ids = {c["id"] for c in ctrl}
        req_ids = {r["id"] for r in req}

        # Reverse link: control -> requirements
        control_to_requirements: Dict[str, List[str]] = {c: [] for c in ctrl_ids}
        for r in req:
            for cid in r.get("linked_control_ids", []):
                if cid in control_to_requirements:
                    control_to_requirements[cid].append(r["id"])

        # Reverse link: requirement -> tests
        requirement_to_tests: Dict[str, List[str]] = {r: [] for r in req_ids}
        for t in tests:
            for rid in t.get("linked_requirement_ids", []):
                if rid in requirement_to_tests:
                    requirement_to_tests[rid].append(t["id"])

        # Reverse link: control -> threats
        control_to_threats: Dict[str, List[str]] = {c: [] for c in ctrl_ids}
        for t in tp:
            for cid in t.get("suggested_control_ids", []):
                if cid in control_to_threats:
                    control_to_threats[cid].append(t["id"])

        return {
            "control_to_requirements": control_to_requirements,
            "requirement_to_tests": requirement_to_tests,
            "control_to_threats": control_to_threats,
        }
