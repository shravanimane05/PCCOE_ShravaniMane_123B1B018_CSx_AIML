"""Dense Retriever for AutoTARA AI using BAAI/bge-small-en-v1.5 and ChromaDB."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import numpy as np

from autotara.config import get_config
from autotara.retrieval.base import (
    RetrievalResult,
    build_pattern_document,
    filter_candidates,
)

BGE_QUERY_PREFIX = "Represent this sentence for searching relevant passages: "
DENSE_MODEL_NAME = "BAAI/bge-small-en-v1.5"


class DenseRetriever:
    """Dense semantic retriever using BAAI/bge-small-en-v1.5 and ChromaDB."""

    def __init__(
        self,
        patterns: List[Dict[str, Any]],
        persist_dir: Optional[Path] = None,
        random_seed: int = 42,
    ):
        self.patterns = patterns
        self.pattern_map = {p["id"]: p for p in patterns}
        self.random_seed = random_seed
        self.is_available = False
        self.status = "NOT_RUN"
        self.error_message: Optional[str] = None
        self.model = None
        self.chroma_client = None
        self.collection = None

        config = get_config()
        self.persist_dir = persist_dir or (config.root_dir / config.retrieval_config.get("chroma_persist_dir", "Code/data/chroma_db"))

        self._initialize()

    def _initialize(self) -> None:
        """Initialize sentence-transformers model and ChromaDB collection."""
        try:
            import sentence_transformers
            import chromadb

            # Set seeds for reproducibility
            np.random.seed(self.random_seed)

            # Load strictly BAAI/bge-small-en-v1.5 (Rule 3)
            self.model = sentence_transformers.SentenceTransformer(DENSE_MODEL_NAME)

            # Ensure persist directory exists
            self.persist_dir.mkdir(parents=True, exist_ok=True)
            self.chroma_client = chromadb.PersistentClient(path=str(self.persist_dir))

            collection_name = "autotara_threat_patterns"
            # Delete if exists to rebuild fresh
            try:
                self.chroma_client.delete_collection(name=collection_name)
            except Exception:
                pass

            self.collection = self.chroma_client.create_collection(
                name=collection_name,
                metadata={"hnsw:space": "cosine"},
            )

            # Index threat patterns
            self._index_patterns()
            self.is_available = True
            self.status = "AVAILABLE"

        except Exception as e:
            self.is_available = False
            self.status = "NOT_RUN"
            self.error_message = (
                f"Dense retrieval could not be initialized: {e}. "
                f"To run manually: pip install sentence-transformers chromadb; "
                f"python -c \"import sentence_transformers; sentence_transformers.SentenceTransformer('{DENSE_MODEL_NAME}')\""
            )

    def _index_patterns(self) -> None:
        """Encode and insert threat patterns into ChromaDB."""
        if not self.collection or not self.model:
            return

        doc_texts = [build_pattern_document(p) for p in self.patterns]
        embeddings = self.model.encode(doc_texts, normalize_embeddings=True).tolist()

        ids = [p["id"] for p in self.patterns]
        metadatas = [
            {
                "id": p["id"],
                "trust_boundary": p.get("trust_boundary", ""),
                "applicable_asset_types": ",".join(p.get("applicable_asset_types", [])),
                "title": p.get("title", ""),
            }
            for p in self.patterns
        ]

        self.collection.add(
            ids=ids,
            embeddings=embeddings,
            documents=doc_texts,
            metadatas=metadatas,
        )

    def search(
        self,
        query: str,
        top_k: int = 5,
        asset_type: Optional[str] = None,
        trust_boundary_ids: Optional[List[str]] = None,
        baseline_version: str = "v1",
        enable_filtering: bool = True,
    ) -> List[RetrievalResult]:
        """Search threat patterns using dense embeddings and ChromaDB.

        Rules:
        - Query instruction prefix: BGE_QUERY_PREFIX
        - Filtering applied BEFORE ranking (Rule 2)
        - TB-05 excluded for v1 baseline
        """
        if not self.is_available or not self.model or not self.collection:
            return []

        # Filter candidates first (Rule 2)
        candidates = filter_candidates(
            self.patterns,
            asset_type=asset_type,
            trust_boundary_ids=trust_boundary_ids,
            baseline_version=baseline_version,
            enable_filtering=enable_filtering,
        )

        if not candidates:
            return []

        candidate_ids = {c["id"] for c in candidates}

        # Rule 3: BGE query instruction prefix
        prefixed_query = f"{BGE_QUERY_PREFIX}{query}"
        query_embedding = self.model.encode([prefixed_query], normalize_embeddings=True)[0].tolist()

        # Query ChromaDB (querying all or filtering by IDs)
        results_raw = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=len(self.patterns),
        )

        retrieved_ids = results_raw["ids"][0] if results_raw["ids"] else []
        distances = results_raw["distances"][0] if results_raw.get("distances") else []

        ranked_results: List[RetrievalResult] = []
        rank = 1

        for pid, dist in zip(retrieved_ids, distances):
            if pid not in candidate_ids:
                continue

            pattern = self.pattern_map[pid]
            # Convert cosine distance to similarity score
            score = 1.0 - float(dist)
            snippet = pattern.get("description", "")[:200]

            ranked_results.append(
                RetrievalResult(
                    pattern_id=pattern["id"],
                    score=score,
                    rank=rank,
                    retrieval_mode="dense",
                    matched_snippet=snippet,
                    title=pattern.get("title"),
                    trust_boundary=pattern.get("trust_boundary"),
                    applicable_asset_types=pattern.get("applicable_asset_types", []),
                )
            )
            rank += 1
            if len(ranked_results) >= top_k:
                break

        return ranked_results
