"""Traceability Graph and Completeness Validator for AutoTARA AI using NetworkX.

Constructs directed graph:
Asset -> Interface -> Threat -> Risk -> Control -> Requirement -> Test -> Review Decision

Enforces human-in-the-loop review decisions and validates end-to-end completeness.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from autotara.architecture_analyzer import ArchitectureAnalyzer
from autotara.data_loader import DataLoader
from autotara.risk_engine import RiskEngine


@dataclass
class CompletenessReport:
    total_threats: int
    complete_threats: int
    completeness_percentage: float
    threats_missing_controls: List[str] = field(default_factory=list)
    threats_missing_requirements: List[str] = field(default_factory=list)
    threats_missing_tests: List[str] = field(default_factory=list)
    is_fully_traceable: bool = False


class TraceabilityGraph:
    """NetworkX directed traceability graph for AutoTARA AI."""

    def __init__(
        self,
        loader: Optional[DataLoader] = None,
        analyzer: Optional[ArchitectureAnalyzer] = None,
    ):
        self.loader = loader or DataLoader()
        self.analyzer = analyzer or ArchitectureAnalyzer.from_loader(self.loader)
        self.graph = nx.DiGraph()
        self.kb = self.loader.load_all_knowledge_base()

        # Derived links
        self.derived = self.loader.build_derived_traceability(
            self.kb["threat_patterns"],
            self.kb["controls"],
            self.kb["requirements"],
            self.kb["verification_tests"],
        )

        self._build_graph()

    def _build_graph(self) -> None:
        """Construct the NetworkX directed traceability graph."""
        patterns = {p["id"]: p for p in self.kb["threat_patterns"]}
        controls = {c["id"]: c for c in self.kb["controls"]}
        requirements = {r["id"]: r for r in self.kb["requirements"]}
        tests = {t["id"]: t for t in self.kb["verification_tests"]}

        ctrl_to_reqs = self.derived["control_to_requirements"]
        req_to_tests = self.derived["requirement_to_tests"]

        # 1. Assets and Interfaces
        for aid, asset in self.analyzer.assets.items():
            self.graph.add_node(aid, node_type="asset", name=asset.get("name", ""))
            surface = self.analyzer.derive_attack_surface(aid)

            for if_id in surface.interface_ids:
                iface = self.analyzer.get_interface(if_id)
                iface_name = iface.get("name", "") if iface else if_id
                self.graph.add_node(if_id, node_type="interface", name=iface_name)
                self.graph.add_edge(aid, if_id)

                # Link interfaces to relevant threats matching trust boundary
                tb_id = iface.get("trust_boundary_id") if iface else None
                if tb_id:
                    for pid, pat in patterns.items():
                        if pat.get("trust_boundary") == tb_id:
                            self.graph.add_node(pid, node_type="threat", title=pat.get("title", ""))
                            self.graph.add_edge(if_id, pid)

        # 2. Threats -> Risk, Control, Requirement, Test, Review Decision
        for pid, pat in patterns.items():
            if not self.graph.has_node(pid):
                self.graph.add_node(pid, node_type="threat", title=pat.get("title", ""))

            # Threat -> Risk (Default prototype moderate risk: impact 3, feasibility 3)
            risk_id = f"RISK-{pid}"
            self.graph.add_node(risk_id, node_type="risk", impact=3, feasibility=3, score=9, band="Medium")
            self.graph.add_edge(pid, risk_id)

            # Risk -> Review Decision (human-in-the-loop)
            decision_id = f"DECISION-{pid}"
            self.graph.add_node(
                decision_id,
                node_type="review_decision",
                status="DRAFT_NEEDS_HUMAN_REVIEW",
                reviewer=None,
            )
            self.graph.add_edge(risk_id, decision_id)

            # Threat -> Controls
            suggested_ctrls = pat.get("suggested_control_ids", [])
            for cid in suggested_ctrls:
                ctrl = controls.get(cid)
                if ctrl:
                    self.graph.add_node(cid, node_type="control", name=ctrl.get("name", ""))
                    self.graph.add_edge(pid, cid)

                # Control -> Requirements
                linked_reqs = ctrl_to_reqs.get(cid, [])
                for rid in linked_reqs:
                    req = requirements.get(rid)
                    if req:
                        self.graph.add_node(rid, node_type="requirement", title=req.get("title", ""))
                        self.graph.add_edge(cid, rid)

                    # Requirement -> Tests
                    linked_tests = req_to_tests.get(rid, [])
                    for tid in linked_tests:
                        test_case = tests.get(tid)
                        if test_case:
                            self.graph.add_node(tid, node_type="test", title=test_case.get("title", ""))
                            self.graph.add_edge(rid, tid)

    def validate_completeness(self) -> CompletenessReport:
        """Validate traceability completeness from Threat -> Control -> Requirement -> Test.

        Returns report with list of missing links and completeness percentage.
        """
        threat_nodes = [n for n, d in self.graph.nodes(data=True) if d.get("node_type") == "threat"]
        total_threats = len(threat_nodes)

        missing_ctrls: List[str] = []
        missing_reqs: List[str] = []
        missing_tests: List[str] = []

        complete_count = 0

        for pid in threat_nodes:
            # Check controls (successors with node_type == "control")
            ctrl_successors = [
                succ for succ in self.graph.successors(pid)
                if self.graph.nodes[succ].get("node_type") == "control"
            ]

            if not ctrl_successors:
                missing_ctrls.append(pid)
                continue

            # Check requirements
            has_req = False
            for cid in ctrl_successors:
                req_successors = [
                    succ for succ in self.graph.successors(cid)
                    if self.graph.nodes[succ].get("node_type") == "requirement"
                ]
                if req_successors:
                    has_req = True
                    break

            if not has_req:
                missing_reqs.append(pid)
                continue

            # Check tests
            has_test = False
            for cid in ctrl_successors:
                for rid in self.graph.successors(cid):
                    if self.graph.nodes[rid].get("node_type") != "requirement":
                        continue
                    test_successors = [
                        succ for succ in self.graph.successors(rid)
                        if self.graph.nodes[succ].get("node_type") == "test"
                    ]
                    if test_successors:
                        has_test = True
                        break
                if has_test:
                    break

            if not has_test:
                missing_tests.append(pid)
                continue

            complete_count += 1

        pct = (complete_count / total_threats * 100.0) if total_threats > 0 else 0.0

        return CompletenessReport(
            total_threats=total_threats,
            complete_threats=complete_count,
            completeness_percentage=round(pct, 2),
            threats_missing_controls=missing_ctrls,
            threats_missing_requirements=missing_reqs,
            threats_missing_tests=missing_tests,
            is_fully_traceable=(complete_count == total_threats),
        )

    def get_subgraph_for_threat(self, threat_id: str) -> nx.DiGraph:
        """Extract reachable subgraph starting from a specific threat pattern."""
        reachable = nx.descendants(self.graph, threat_id)
        reachable.add(threat_id)
        return self.graph.subgraph(reachable).copy()
