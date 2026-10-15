"""Change-impact analysis for AutoTARA AI (Change-Aware TARA).

Compares two architecture baselines and reports the TARA artifacts that must be
reassessed after an architecture change: threats, controls, cybersecurity
requirements, verification tests, and the assets that host the change.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from autotara.data_loader import DataLoader


@dataclass
class ChangeImpactReport:
    """Diff between two baselines plus the TARA artifacts needing reassessment."""

    base_version: str
    target_version: str
    base_name: str
    target_name: str
    added_components: List[Dict[str, Any]] = field(default_factory=list)
    removed_components: List[Dict[str, Any]] = field(default_factory=list)
    added_interfaces: List[Dict[str, Any]] = field(default_factory=list)
    removed_interfaces: List[Dict[str, Any]] = field(default_factory=list)
    added_trust_boundaries: List[Dict[str, Any]] = field(default_factory=list)
    removed_trust_boundaries: List[Dict[str, Any]] = field(default_factory=list)
    added_trust_zones: List[Dict[str, Any]] = field(default_factory=list)
    removed_trust_zones: List[Dict[str, Any]] = field(default_factory=list)
    added_data_flows: List[Dict[str, Any]] = field(default_factory=list)
    removed_data_flows: List[Dict[str, Any]] = field(default_factory=list)
    impacted_assets: List[Dict[str, Any]] = field(default_factory=list)
    impacted_threats: List[Dict[str, Any]] = field(default_factory=list)
    impacted_controls: List[Dict[str, Any]] = field(default_factory=list)
    impacted_requirements: List[Dict[str, Any]] = field(default_factory=list)
    impacted_tests: List[Dict[str, Any]] = field(default_factory=list)
    checklist: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.added_components
            or self.removed_components
            or self.added_interfaces
            or self.removed_interfaces
            or self.added_trust_boundaries
            or self.removed_trust_boundaries
            or self.added_data_flows
            or self.removed_data_flows
            or self.added_trust_zones
            or self.removed_trust_zones
        )

    def counts(self) -> Dict[str, int]:
        return {
            "components": len(self.added_components) - len(self.removed_components),
            "interfaces": len(self.added_interfaces) - len(self.removed_interfaces),
            "trust_boundaries": len(self.added_trust_boundaries) - len(self.removed_trust_boundaries),
            "data_flows": len(self.added_data_flows) - len(self.removed_data_flows),
            "impacted_assets": len(self.impacted_assets),
            "impacted_threats": len(self.impacted_threats),
            "impacted_controls": len(self.impacted_controls),
            "impacted_requirements": len(self.impacted_requirements),
            "impacted_tests": len(self.impacted_tests),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_version": self.base_version,
            "target_version": self.target_version,
            "base_name": self.base_name,
            "target_name": self.target_name,
            "counts": self.counts(),
            "added_components": self.added_components,
            "removed_components": self.removed_components,
            "added_interfaces": self.added_interfaces,
            "removed_interfaces": self.removed_interfaces,
            "added_trust_boundaries": self.added_trust_boundaries,
            "removed_trust_boundaries": self.removed_trust_boundaries,
            "added_trust_zones": self.added_trust_zones,
            "removed_trust_zones": self.removed_trust_zones,
            "added_data_flows": self.added_data_flows,
            "removed_data_flows": self.removed_data_flows,
            "impacted_assets": self.impacted_assets,
            "impacted_threats": self.impacted_threats,
            "impacted_controls": self.impacted_controls,
            "impacted_requirements": self.impacted_requirements,
            "impacted_tests": self.impacted_tests,
            "reassessment_checklist": self.checklist,
        }


def _diff(base: Dict[str, Any], target: Dict[str, Any], key: str) -> tuple:
    base_items = {item["id"]: item for item in base.get(key, [])}
    target_items = {item["id"]: item for item in target.get(key, [])}
    added = [target_items[i] for i in sorted(set(target_items) - set(base_items))]
    removed = [base_items[i] for i in sorted(set(base_items) - set(target_items))]
    return added, removed


def _protocol_tokens(protocol: str) -> set:
    return {tok.strip().lower() for tok in protocol.replace("/", " ").replace("-", " ").split() if tok.strip()}


def build_change_impact(
    loader: Optional[DataLoader] = None,
    base_version: str = "v1",
    target_version: str = "v2",
) -> ChangeImpactReport:
    """Compare two architecture baselines and derive affected TARA artifacts."""
    dl = loader or DataLoader()
    base = dl.load_architecture(base_version)
    target = dl.load_architecture(target_version)

    report = ChangeImpactReport(
        base_version=base_version,
        target_version=target_version,
        base_name=base.get("name", base_version),
        target_name=target.get("name", target_version),
    )

    (
        report.added_components,
        report.removed_components,
    ) = _diff(base, target, "components")
    (
        report.added_interfaces,
        report.removed_interfaces,
    ) = _diff(base, target, "interfaces")
    (
        report.added_trust_boundaries,
        report.removed_trust_boundaries,
    ) = _diff(base, target, "trust_boundaries")
    (
        report.added_trust_zones,
        report.removed_trust_zones,
    ) = _diff(base, target, "trust_zones")
    (
        report.added_data_flows,
        report.removed_data_flows,
    ) = _diff(base, target, "data_flows")

    added_tb_ids = {tb["id"] for tb in report.added_trust_boundaries}
    added_component_ids = {c["id"] for c in report.added_components}
    added_protocols: set = set()
    for iface in report.added_interfaces:
        added_protocols |= _protocol_tokens(iface.get("protocol", ""))
        if iface.get("trust_boundary_id"):
            added_tb_ids.add(iface["trust_boundary_id"])

    # Assets hosted on an added component, or of a type touched by a new-boundary threat.
    for asset in target.get("assets", []):
        hosted = set(asset.get("hosted_on", []))
        if hosted & added_component_ids:
            report.impacted_assets.append(
                {
                    "id": asset["id"],
                    "name": asset.get("name", ""),
                    "type": asset.get("type", ""),
                    "reason": f"Hosts added component(s) {', '.join(sorted(hosted & added_component_ids))}.",
                }
            )

    patterns = dl.load_threat_patterns()
    controls = {c["id"]: c for c in dl.load_controls()}
    requirements = {r["id"]: r for r in dl.load_requirements()}
    tests = {t["id"]: t for t in dl.load_verification_tests()}
    derived = dl.build_derived_traceability(patterns, list(controls.values()), list(requirements.values()), list(tests.values()))

    control_ids: List[str] = []
    requirement_ids: List[str] = []
    test_ids: List[str] = []

    for pattern in patterns:
        reasons: List[str] = []
        tb = pattern.get("trust_boundary")
        if tb in added_tb_ids:
            tb_name = next((b.get("name", "") for b in report.added_trust_boundaries if b["id"] == tb), "")
            reasons.append(
                f"Targets newly introduced trust boundary {tb}"
                + (f" ({tb_name})" if tb_name else "")
                + "; dormant in the previous baseline."
            )

        iface_types = {t.lower() for t in pattern.get("interface_types", [])}
        overlap = iface_types & added_protocols
        if overlap:
            reasons.append(
                "Matches added interface protocol token(s): "
                + ", ".join(sorted(overlap))
                + "; a new exposure path now exists."
            )

        if not reasons:
            continue

        asset_types = pattern.get("applicable_asset_types", [])
        for asset in target.get("assets", []):
            if asset.get("type") in asset_types and not any(
                a["id"] == asset["id"] for a in report.impacted_assets
            ):
                host_names = ", ".join(
                    next((c["name"] for c in target["components"] if c["id"] == cid), cid)
                    for cid in asset.get("hosted_on", [])
                )
                report.impacted_assets.append(
                    {
                        "id": asset["id"],
                        "name": asset.get("name", ""),
                        "type": asset.get("type", ""),
                        "reason": f"Asset type is in scope of impacted threat {pattern['id']} "
                        + (f"(hosted on {host_names})." if host_names else "."),
                    }
                )

        report.impacted_threats.append(
            {
                "id": pattern["id"],
                "title": pattern.get("title", ""),
                "trust_boundary": tb,
                "stride_category": pattern.get("stride_category", ""),
                "freshness_status": pattern.get("freshness_status", ""),
                "owner": pattern.get("owner", ""),
                "next_review_date": pattern.get("next_review_date", ""),
                "reasons": reasons,
            }
        )

        for cid in pattern.get("suggested_control_ids", []):
            if cid in controls and cid not in control_ids:
                control_ids.append(cid)

    for cid in control_ids:
        ctrl = controls[cid]
        reqs = [r for r in derived["control_to_requirements"].get(cid, []) if r in requirements]
        report.impacted_controls.append(
            {
                "id": cid,
                "name": ctrl.get("name", ""),
                "type": ctrl.get("type", ""),
                "linked_requirements": reqs,
                "reason": "Suggested by a threat pattern triggered by the architecture change.",
            }
        )
        for rid in reqs:
            if rid in requirement_ids:
                continue
            requirement_ids.append(rid)
            req = requirements[rid]
            linked_tests = [t for t in derived["requirement_to_tests"].get(rid, []) if t in tests]
            report.impacted_requirements.append(
                {
                    "id": rid,
                    "title": req.get("title", ""),
                    "category": req.get("category", ""),
                    "linked_tests": linked_tests,
                    "reason": f"Cybersecurity requirement covering changed control {cid}.",
                }
            )
            for tid in linked_tests:
                if tid in test_ids:
                    continue
                test_ids.append(tid)
                report.impacted_tests.append(
                    {
                        "id": tid,
                        "title": tests[tid].get("title", ""),
                        "reason": f"Verification test for requirement {rid} requiring re-execution.",
                    }
                )

    report.checklist = _build_checklist(report, target)
    return report


def _build_checklist(report: ChangeImpactReport, target: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Derive a concrete reassessment checklist for the engineering review."""
    items: List[Dict[str, Any]] = []

    for comp in report.added_components:
        items.append(
            {
                "item": f"Re-analyze attack surface introduced by {comp['id']} {comp['name']}",
                "artifact_type": "Architecture",
                "status": "Requires reassessment",
                "rationale": comp.get("description", "New component in the target baseline."),
            }
        )

    for iface in report.added_interfaces:
        tb = iface.get("trust_boundary_id", "")
        items.append(
            {
                "item": f"Review trust boundary crossing at {iface['id']} {iface['name']}",
                "artifact_type": "Interface / Trust Boundary",
                "status": "Requires reassessment",
                "rationale": f"New protocol exposure ({iface.get('protocol', 'n/a')}) crossing {tb or 'an unassigned boundary'}.",
            }
        )

    for threat in report.impacted_threats:
        items.append(
            {
                "item": f"Re-run threat analysis for {threat['id']} {threat['title']}",
                "artifact_type": "Threat",
                "status": "Requires reassessment",
                "rationale": " ".join(threat["reasons"]),
            }
        )
        if threat.get("freshness_status") in ("Review Due", "Outdated"):
            items.append(
                {
                    "item": f"Confirm knowledge freshness of {threat['id']} before reuse",
                    "artifact_type": "Threat knowledge",
                    "status": threat["freshness_status"],
                    "rationale": f"Owner {threat.get('owner', 'n/a')}; next review {threat.get('next_review_date', 'n/a')}.",
                }
            )

    for control in report.impacted_controls:
        items.append(
            {
                "item": f"Verify control coverage {control['id']} {control['name']}",
                "artifact_type": "Control",
                "status": "Requires reassessment",
                "rationale": control["reason"],
            }
        )

    for req in report.impacted_requirements:
        items.append(
            {
                "item": f"Update requirement {req['id']} {req['title']}",
                "artifact_type": "Requirement",
                "status": "Requires reassessment",
                "rationale": req["reason"],
            }
        )

    for test in report.impacted_tests:
        items.append(
            {
                "item": f"Re-execute verification test {test['id']} {test['title']}",
                "artifact_type": "Verification test",
                "status": "Requires reassessment",
                "rationale": test["reason"],
            }
        )

    return items
