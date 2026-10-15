"""Unified index builder and retriever coordinator for AutoTARA AI."""

from typing import Any, Dict, List, Optional

from autotara.config import get_config
from autotara.data_loader import DataLoader
from autotara.retrieval.base import RetrievalResult
from autotara.retrieval.bm25 import BM25Retriever
from autotara.retrieval.dense import DenseRetriever
from autotara.retrieval.hybrid import HybridRetriever
from autotara.retrieval.tfidf import TFIDFRetriever


class IndexBuilder:
    """Coordinates and provides access to TF-IDF, BM25, Dense, and Hybrid retrievers."""

    def __init__(
        self,
        patterns: Optional[List[Dict[str, Any]]] = None,
        loader: Optional[DataLoader] = None,
    ):
        self.loader = loader or DataLoader()
        self.patterns = patterns or self.loader.load_threat_patterns()

        # Initialize individual indexers
        self.tfidf = TFIDFRetriever(self.patterns)
        self.bm25 = BM25Retriever(self.patterns)
        self.dense = DenseRetriever(self.patterns)
        self.hybrid = HybridRetriever(
            self.patterns,
            bm25_retriever=self.bm25,
            dense_retriever=self.dense,
        )

    def get_mode_status(self) -> Dict[str, str]:
        """Return execution readiness status for each retrieval mode."""
        return {
            "tfidf": "AVAILABLE",
            "bm25": "AVAILABLE",
            "dense": "AVAILABLE" if self.dense.is_available else "NOT_RUN",
            "hybrid": "AVAILABLE (Full)" if self.dense.is_available else "AVAILABLE (BM25 Fallback)",
        }

    def search(
        self,
        query: str,
        mode: str = "hybrid",
        top_k: int = 5,
        asset_type: Optional[str] = None,
        trust_boundary_ids: Optional[List[str]] = None,
        baseline_version: str = "v1",
        enable_filtering: bool = True,
    ) -> List[RetrievalResult]:
        """Search using the specified retrieval mode ('tfidf', 'bm25', 'dense', 'hybrid')."""
        mode_lower = mode.lower()
        if mode_lower == "tfidf":
            return self.tfidf.search(
                query,
                top_k=top_k,
                asset_type=asset_type,
                trust_boundary_ids=trust_boundary_ids,
                baseline_version=baseline_version,
                enable_filtering=enable_filtering,
            )
        elif mode_lower == "bm25":
            return self.bm25.search(
                query,
                top_k=top_k,
                asset_type=asset_type,
                trust_boundary_ids=trust_boundary_ids,
                baseline_version=baseline_version,
                enable_filtering=enable_filtering,
            )
        elif mode_lower == "dense":
            return self.dense.search(
                query,
                top_k=top_k,
                asset_type=asset_type,
                trust_boundary_ids=trust_boundary_ids,
                baseline_version=baseline_version,
                enable_filtering=enable_filtering,
            )
        elif mode_lower == "hybrid":
            return self.hybrid.search(
                query,
                top_k=top_k,
                asset_type=asset_type,
                trust_boundary_ids=trust_boundary_ids,
                baseline_version=baseline_version,
                enable_filtering=enable_filtering,
            )
        else:
            raise ValueError(f"Unknown retrieval mode: '{mode}'. Must be tfidf, bm25, dense, or hybrid.")
