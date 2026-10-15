"""BM25 Retriever for AutoTARA AI using rank-bm25."""

import re
from typing import Any, Dict, List, Optional
import numpy as np
from rank_bm25 import BM25Okapi

from autotara.retrieval.base import (
    RetrievalResult,
    build_pattern_document,
    filter_candidates,
)


def simple_tokenize(text: str) -> List[str]:
    """Tokenize text into lowercase alphanumeric tokens."""
    return re.findall(r"\b[a-zA-Z0-9_\-]+\b", text.lower())


class BM25Retriever:
    """BM25Okapi lexical retriever for threat pattern matching."""

    def __init__(self, patterns: List[Dict[str, Any]]):
        self.patterns = patterns
        self.pattern_map = {p["id"]: p for p in patterns}
        self.corpus_docs = [build_pattern_document(p) for p in self.patterns]
        self.tokenized_corpus = [simple_tokenize(doc) for doc in self.corpus_docs]

    def search(
        self,
        query: str,
        top_k: int = 5,
        asset_type: Optional[str] = None,
        trust_boundary_ids: Optional[List[str]] = None,
        baseline_version: str = "v1",
        enable_filtering: bool = True,
    ) -> List[RetrievalResult]:
        """Search threat patterns using BM25.

        Rules:
        - Candidate filtering applied BEFORE ranking (Rule 2).
        - Returns structured RetrievalResult list (Rule 5).
        """
        candidates = filter_candidates(
            self.patterns,
            asset_type=asset_type,
            trust_boundary_ids=trust_boundary_ids,
            baseline_version=baseline_version,
            enable_filtering=enable_filtering,
        )

        if not candidates:
            return []

        # Tokenized candidates
        candidate_docs = [build_pattern_document(c) for c in candidates]
        tokenized_candidates = [simple_tokenize(doc) for doc in candidate_docs]
        bm25_model = BM25Okapi(tokenized_candidates)

        query_tokens = simple_tokenize(query)
        if not query_tokens:
            return []

        scores = bm25_model.get_scores(query_tokens)
        ranked_order = np.argsort(-scores)

        results: List[RetrievalResult] = []
        for rank, idx in enumerate(ranked_order[:top_k], start=1):
            pattern = candidates[idx]
            score = float(scores[idx])
            snippet = pattern.get("description", "")[:200]
            results.append(
                RetrievalResult(
                    pattern_id=pattern["id"],
                    score=score,
                    rank=rank,
                    retrieval_mode="bm25",
                    matched_snippet=snippet,
                    title=pattern.get("title"),
                    trust_boundary=pattern.get("trust_boundary"),
                    applicable_asset_types=pattern.get("applicable_asset_types", []),
                )
            )

        return results
