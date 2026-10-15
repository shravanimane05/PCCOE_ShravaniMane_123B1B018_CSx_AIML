"""Hybrid Retriever for AutoTARA AI combining Dense and BM25 via Reciprocal Rank Fusion (RRF)."""

from typing import Any, Dict, List, Optional

from autotara.config import get_config
from autotara.retrieval.base import RetrievalResult
from autotara.retrieval.bm25 import BM25Retriever
from autotara.retrieval.dense import DenseRetriever


class HybridRetriever:
    """Hybrid retriever combining Dense (semantic) and BM25 (lexical) via RRF."""

    def __init__(
        self,
        patterns: List[Dict[str, Any]],
        bm25_retriever: Optional[BM25Retriever] = None,
        dense_retriever: Optional[DenseRetriever] = None,
        rrf_k: Optional[int] = None,
    ):
        self.patterns = patterns
        self.pattern_map = {p["id"]: p for p in patterns}
        self.bm25 = bm25_retriever or BM25Retriever(patterns)
        self.dense = dense_retriever or DenseRetriever(patterns)

        config = get_config()
        self.rrf_k = rrf_k if rrf_k is not None else config.retrieval_config.get("rrf_k", 60)

    @property
    def dense_is_available(self) -> bool:
        return self.dense.is_available

    def search(
        self,
        query: str,
        top_k: int = 5,
        asset_type: Optional[str] = None,
        trust_boundary_ids: Optional[List[str]] = None,
        baseline_version: str = "v1",
        enable_filtering: bool = True,
    ) -> List[RetrievalResult]:
        """Search threat patterns using Hybrid RRF of Dense and BM25.

        Rule 4: If dense is NOT_RUN, hybrid falls back to BM25 and says so in its output.
        """
        # If dense is not available, gracefully fall back to BM25
        if not self.dense_is_available:
            bm25_results = self.bm25.search(
                query=query,
                top_k=top_k,
                asset_type=asset_type,
                trust_boundary_ids=trust_boundary_ids,
                baseline_version=baseline_version,
                enable_filtering=enable_filtering,
            )
            for res in bm25_results:
                res.retrieval_mode = "hybrid"
                res.fallback_note = (
                    "Dense retrieval is NOT_RUN; hybrid fell back to BM25. "
                    f"Reason: {self.dense.error_message}"
                )
            return bm25_results

        # Dense is available: retrieve up to 20 from each for fusion
        pool_size = max(top_k * 3, 20)
        bm25_results = self.bm25.search(
            query=query,
            top_k=pool_size,
            asset_type=asset_type,
            trust_boundary_ids=trust_boundary_ids,
            baseline_version=baseline_version,
            enable_filtering=enable_filtering,
        )
        dense_results = self.dense.search(
            query=query,
            top_k=pool_size,
            asset_type=asset_type,
            trust_boundary_ids=trust_boundary_ids,
            baseline_version=baseline_version,
            enable_filtering=enable_filtering,
        )

        # Reciprocal Rank Fusion
        rrf_scores: Dict[str, float] = {}

        for res in bm25_results:
            rrf_scores[res.pattern_id] = rrf_scores.get(res.pattern_id, 0.0) + (1.0 / (self.rrf_k + res.rank))

        for res in dense_results:
            rrf_scores[res.pattern_id] = rrf_scores.get(res.pattern_id, 0.0) + (1.0 / (self.rrf_k + res.rank))

        # Sort by RRF score descending
        sorted_pids = sorted(rrf_scores.keys(), key=lambda pid: rrf_scores[pid], reverse=True)

        results: List[RetrievalResult] = []
        for rank, pid in enumerate(sorted_pids[:top_k], start=1):
            pattern = self.pattern_map[pid]
            snippet = pattern.get("description", "")[:200]
            results.append(
                RetrievalResult(
                    pattern_id=pid,
                    score=rrf_scores[pid],
                    rank=rank,
                    retrieval_mode="hybrid",
                    matched_snippet=snippet,
                    title=pattern.get("title"),
                    trust_boundary=pattern.get("trust_boundary"),
                    applicable_asset_types=pattern.get("applicable_asset_types", []),
                    fallback_note=None,
                )
            )

        return results
