"""Mitigation Engine for AutoTARA AI.

Maps threat patterns to suggested controls, drafts formal cybersecurity
requirements by populating templates with asset names, and links verification tests.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from autotara.data_loader import DataLoader


@dataclass
class DraftedRequirement:
    id: str
    title: str
    category: str
    requirement_text: str
    linked_control_id: str
    tests: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class MitigationBundle:
    threat_pattern_id: str
    threat_title: str
    asset_name: str
    controls: List[Dict[str, Any]]
    requirements: List[DraftedRequirement]


class MitigationEngine:
    """Derives controls, requirements, and tests for threat mitigations."""

    def __init__(self, loader: Optional[DataLoader] = None):
        self.loader = loader or DataLoader()
        self.kb = self.loader.load_all_knowledge_base()

        self.patterns: Dict[str, Dict[str, Any]] = {p["id"]: p for p in self.kb["threat_patterns"]}
        self.controls: Dict[str, Dict[str, Any]] = {c["id"]: c for c in self.kb["controls"]}
        self.requirements: Dict[str, Dict[str, Any]] = {r["id"]: r for r in self.kb["requirements"]}
        self.tests: Dict[str, Dict[str, Any]] = {t["id"]: t for t in self.kb["verification_tests"]}

        # Derived reverse maps
        derived = self.loader.build_derived_traceability(
            self.kb["threat_patterns"],
            self.kb["controls"],
            self.kb["requirements"],
            self.kb["verification_tests"],
        )
        self.control_to_reqs = derived["control_to_requirements"]
        self.req_to_tests = derived["requirement_to_tests"]

    def draft_mitigation_bundle(
        self,
        threat_pattern_id: str,
        asset_name: str = "Target Asset",
    ) -> MitigationBundle:
        """Construct full mitigation bundle with controls, drafted requirements, and tests."""
        pattern = self.patterns.get(threat_pattern_id)
        if not pattern:
            raise KeyError(f"Threat pattern '{threat_pattern_id}' not found.")

        ctrl_ids = pattern.get("suggested_control_ids", [])
        matched_controls: List[Dict[str, Any]] = []
        drafted_reqs: List[DraftedRequirement] = []

        seen_req_ids = set()

        for cid in ctrl_ids:
            ctrl = self.controls.get(cid)
            if ctrl:
                matched_controls.append(ctrl)

            # Find requirements pointing to this control
            req_ids_for_ctrl = self.control_to_reqs.get(cid, [])
            for rid in req_ids_for_ctrl:
                if rid in seen_req_ids:
                    continue
                seen_req_ids.add(rid)

                req = self.requirements.get(rid)
                if not req:
                    continue

                # Template filling
                raw_template = req.get("text_template", "The {asset} shall maintain security.")
                filled_text = raw_template.replace("{asset}", asset_name)

                # Find tests pointing to this requirement
                tids = self.req_to_tests.get(rid, [])
                linked_tests = [self.tests[t] for t in tids if t in self.tests]

                drafted_reqs.append(
                    DraftedRequirement(
                        id=rid,
                        title=req.get("title", ""),
                        category=req.get("category", ""),
                        requirement_text=filled_text,
                        linked_control_id=cid,
                        tests=linked_tests,
                    )
                )

        return MitigationBundle(
            threat_pattern_id=threat_pattern_id,
            threat_title=pattern.get("title", ""),
            asset_name=asset_name,
            controls=matched_controls,
            requirements=drafted_reqs,
        )
