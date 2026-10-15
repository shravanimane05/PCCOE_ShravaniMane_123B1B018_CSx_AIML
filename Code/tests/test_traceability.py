"""Pytest suite for TraceabilityGraph and completeness validator."""

import pytest
import networkx as nx
from autotara.traceability import TraceabilityGraph, CompletenessReport


@pytest.fixture
def trace_graph():
    return TraceabilityGraph()


def test_traceability_graph_node_types(trace_graph):
    """Verify NetworkX graph contains all required node types."""
    g = trace_graph.graph
    node_types = {d.get("node_type") for n, d in g.nodes(data=True)}

    required_types = {
        "asset",
        "interface",
        "threat",
        "risk",
        "control",
        "requirement",
        "test",
        "review_decision",
    }
    assert required_types.issubset(node_types)


def test_traceability_chain_path(trace_graph):
    """Verify directed paths exist from Asset to Control, Requirement, Test, and Review Decision."""
    g = trace_graph.graph

    # Path from A-01 to TP-001
    assert g.has_node("A-01")
    assert g.has_node("TP-001")
    assert nx.has_path(g, "A-01", "TP-001")

    # Path from TP-001 to CTRL-002, REQ-001, TEST-001
    assert nx.has_path(g, "TP-001", "CTRL-002")
    assert nx.has_path(g, "TP-001", "REQ-001")
    assert nx.has_path(g, "TP-001", "TEST-001")

    # Path from TP-001 to Risk and Review Decision
    assert nx.has_path(g, "TP-001", "RISK-TP-001")
    assert nx.has_path(g, "TP-001", "DECISION-TP-001")


def test_traceability_completeness_validation(trace_graph):
    """Verify completeness validation returns 100% completeness on Phase 1 data."""
    report = trace_graph.validate_completeness()
    assert isinstance(report, CompletenessReport)
    assert report.total_threats == 30
    assert report.complete_threats == 30
    assert report.completeness_percentage == 100.0
    assert report.is_fully_traceable is True
    assert report.threats_missing_controls == []
    assert report.threats_missing_requirements == []
    assert report.threats_missing_tests == []
