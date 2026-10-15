"""Pytest suite for AutoTARA AI retrieval modes: TF-IDF, BM25, Dense, and Hybrid."""

import pytest
from autotara.data_loader import DataLoader
from autotara.retrieval.base import filter_candidates
from autotara.retrieval.bm25 import BM25Retriever
from autotara.retrieval.dense import DenseRetriever
from autotara.retrieval.hybrid import HybridRetriever
from autotara.retrieval.index_builder import IndexBuilder
from autotara.retrieval.tfidf import TFIDFRetriever


@pytest.fixture
def loader():
    return DataLoader()


@pytest.fixture
def patterns(loader):
    return loader.load_threat_patterns()


@pytest.fixture
def index_builder(loader):
    return IndexBuilder(loader=loader)


def test_filter_candidates_tb05_excluded_for_v1(patterns):
    """Verify Rule 2: Patterns referencing TB-05 must not appear for the v1 baseline."""
    # When filtering is enabled
    candidates_v1 = filter_candidates(patterns, baseline_version="v1", enable_filtering=True)
    tb_ids_v1 = {c["trust_boundary"] for c in candidates_v1}
    assert "TB-05" not in tb_ids_v1

    # Even when filtering is disabled, TB-05 is excluded for v1 baseline
    candidates_v1_nofilter = filter_candidates(patterns, baseline_version="v1", enable_filtering=False)
    tb_ids_v1_nofilter = {c["trust_boundary"] for c in candidates_v1_nofilter}
    assert "TB-05" not in tb_ids_v1_nofilter

    # In v2 baseline, TB-05 IS included
    candidates_v2 = filter_candidates(patterns, baseline_version="v2", enable_filtering=False)
    tb_ids_v2 = {c["trust_boundary"] for c in candidates_v2}
    assert "TB-05" in tb_ids_v2


def test_filter_candidates_by_asset_type_and_boundary(patterns):
    """Verify Rule 2: Filter candidates by trust boundary ID and asset type BEFORE ranking."""
    # Filter for mobile_app on TB-01
    filtered = filter_candidates(
        patterns,
        asset_type="mobile_app",
        trust_boundary_ids=["TB-01"],
        baseline_version="v1",
        enable_filtering=True,
    )
    for p in filtered:
        assert p["trust_boundary"] == "TB-01"
        assert "mobile_app" in p["applicable_asset_types"]


def test_tfidf_retriever(patterns):
    """Verify TF-IDF returns structured RetrievalResult objects."""
    retriever = TFIDFRetriever(patterns)
    query = "OAuth access token theft and mobile app API bypass"
    results = retriever.search(query, top_k=3, asset_type="mobile_app", trust_boundary_ids=["TB-01"])

    assert len(results) > 0
    top = results[0]
    assert top.pattern_id == "TP-001"
    assert top.retrieval_mode == "tfidf"
    assert top.rank == 1
    assert top.matched_snippet != ""
    assert isinstance(top.score, float)


def test_bm25_retriever(patterns):
    """Verify BM25 returns structured RetrievalResult objects."""
    retriever = BM25Retriever(patterns)
    query = "OTA firmware package signature verification tampering"
    results = retriever.search(query, top_k=3, asset_type="ota_firmware", trust_boundary_ids=["TB-02"])

    assert len(results) > 0
    top = results[0]
    assert top.retrieval_mode == "bm25"
    assert top.rank == 1
    assert top.matched_snippet != ""


def test_dense_retriever_status_and_contract(patterns):
    """Verify Dense retriever status contract per Rule 3."""
    retriever = DenseRetriever(patterns)
    assert retriever.status in ("AVAILABLE", "NOT_RUN")
    if retriever.status == "NOT_RUN":
        assert retriever.is_available is False
        assert retriever.error_message is not None
        assert "BAAI/bge-small-en-v1.5" in retriever.error_message
        results = retriever.search("Test query", top_k=3)
        assert results == []
    else:
        assert retriever.is_available is True
        query = "Compromised TCU injecting malicious CAN frames into vehicle gateway"
        results = retriever.search(query, top_k=3, asset_type="tcu", trust_boundary_ids=["TB-03"])
        assert len(results) > 0
        assert results[0].retrieval_mode == "dense"


def test_hybrid_retriever_execution_and_fallback(patterns):
    """Verify Hybrid retriever execution per Rule 4."""
    retriever = HybridRetriever(patterns)
    query = "Diagnostic UDS security access seed key bypass OBD-II"
    results = retriever.search(query, top_k=3, asset_type="diagnostic_services", trust_boundary_ids=["TB-04"])

    assert len(results) > 0
    top = results[0]
    assert top.pattern_id == "TP-005"
    assert top.retrieval_mode == "hybrid"
    assert top.rank == 1

    if not retriever.dense_is_available:
        assert top.fallback_note is not None
        assert "Dense retrieval is NOT_RUN" in top.fallback_note
    else:
        assert top.fallback_note is None


def test_hybrid_fallback_when_dense_not_run(patterns):
    """Verify Rule 4: If dense is NOT_RUN, hybrid falls back to BM25 and says so in its output."""
    mock_dense = DenseRetriever.__new__(DenseRetriever)
    mock_dense.patterns = patterns
    mock_dense.pattern_map = {p["id"]: p for p in patterns}
    mock_dense.is_available = False
    mock_dense.status = "NOT_RUN"
    mock_dense.error_message = "Mocked offline error"

    hybrid = HybridRetriever(patterns, dense_retriever=mock_dense)
    query = "OAuth access token theft and mobile app API bypass"
    results = hybrid.search(query, top_k=3, asset_type="mobile_app", trust_boundary_ids=["TB-01"])

    assert len(results) > 0
    top = results[0]
    assert top.retrieval_mode == "hybrid"
    assert top.fallback_note is not None
    assert "Dense retrieval is NOT_RUN; hybrid fell back to BM25" in top.fallback_note


def test_index_builder_coordinator(index_builder):
    """Verify IndexBuilder coordinates all 4 modes."""
    status = index_builder.get_mode_status()
    assert status["tfidf"] == "AVAILABLE"
    assert status["bm25"] == "AVAILABLE"
    assert status["dense"] in ("AVAILABLE", "NOT_RUN")
    assert "AVAILABLE" in status["hybrid"]

    modes_to_test = ["tfidf", "bm25", "hybrid"]
    if status["dense"] == "AVAILABLE":
        modes_to_test.append("dense")

    for mode in modes_to_test:
        res = index_builder.search("Firmware signature verification", mode=mode, top_k=2)
        assert len(res) > 0
        assert res[0].retrieval_mode == mode
