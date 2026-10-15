"""TF-IDF Retriever for AutoTARA AI using scikit-learn."""

from typing import Any, Dict, List, Optional
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from autotara.retrieval.base import (
    RetrievalResult,
    build_pattern_document,
    filter_candidates,
)


class TFIDFRetriever:
    """TF-IDF lexical retriever for threat pattern matching."""

    def __init__(self, patterns: List[Dict[str, Any]]):
        self.patterns = patterns
        self.pattern_map = {p["id"]: p for p in patterns}
        self.vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
        self.corpus_docs = [build_pattern_document(p) for p in self.patterns]
        self.doc_matrix = self.vectorizer.fit_transform(self.corpus_docs)

    def search(
        self,
        query: str,
        top_k: int = 5,
        asset_type: Optional[str] = None,
        trust_boundary_ids: Optional[List[str]] = None,
        baseline_version: str = "v1",
        enable_filtering: bool = True,
    ) -> List[RetrievalResult]:
        """Search threat patterns using TF-IDF cosine similarity.

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

        # Get candidate indices in original corpus
        candidate_ids = [c["id"] for c in candidates]
        candidate_indices = [
            i for i, p in enumerate(self.patterns) if p["id"] in candidate_ids
        ]

        query_vec = self.vectorizer.transform([query])
        candidate_matrix = self.doc_matrix[candidate_indices]
        sims = cosine_similarity(query_vec, candidate_matrix).flatten()

        ranked_order = np.argsort(-sims)

        results: List[RetrievalResult] = []
        for rank, idx in enumerate(ranked_order[:top_k], start=1):
            pattern = candidates[idx]
            score = float(sims[idx])
            snippet = pattern.get("description", "")[:200]
            results.append(
                RetrievalResult(
                    pattern_id=pattern["id"],
                    score=score,
                    rank=rank,
                    retrieval_mode="tfidf",
                    matched_snippet=snippet,
                    title=pattern.get("title"),
                    trust_boundary=pattern.get("trust_boundary"),
                    applicable_asset_types=pattern.get("applicable_asset_types", []),
                )
            )

        return results
