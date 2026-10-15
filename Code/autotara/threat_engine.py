"""Threat Engine for AutoTARA AI.

Coordinates architecture attack surface extraction and RAG-based threat identification.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from autotara.architecture_analyzer import ArchitectureAnalyzer, AttackSurfaceContext
from autotara.data_loader import DataLoader
from autotara.retrieval.base import RetrievalResult
from autotara.retrieval.index_builder import IndexBuilder


@dataclass
class ThreatIdentification:
    asset_id: str
    asset_name: str
    query_used: str
    retrieval_mode: str
    results: List[RetrievalResult]


class ThreatEngine:
    """Identifies applicable cybersecurity threats for architecture assets."""

    def __init__(
        self,
        analyzer: Optional[ArchitectureAnalyzer] = None,
        index_builder: Optional[IndexBuilder] = None,
        loader: Optional[DataLoader] = None,
    ):
        self.loader = loader or DataLoader()
        self.analyzer = analyzer or ArchitectureAnalyzer.from_loader(self.loader)
        self.index_builder = index_builder or IndexBuilder(loader=self.loader)

    def identify_threats_for_asset(
        self,
        asset_id: str,
        mode: str = "hybrid",
        top_k: int = 5,
        enable_filtering: bool = True,
        baseline_version: Optional[str] = None,
    ) -> ThreatIdentification:
        """Derive attack surface and retrieve top matching threat patterns for an asset."""
        context = self.analyzer.derive_attack_surface(asset_id)
        query = context.build_query()

        version = baseline_version or getattr(self.analyzer, "version", "v1")

        results = self.index_builder.search(
            query=query,
            mode=mode,
            top_k=top_k,
            asset_type=context.asset_type,
            trust_boundary_ids=context.trust_boundary_ids,
            baseline_version=version,
            enable_filtering=enable_filtering,
        )

        return ThreatIdentification(
            asset_id=asset_id,
            asset_name=context.asset_name,
            query_used=query,
            retrieval_mode=mode,
            results=results,
        )

    def identify_threats_for_all_assets(
        self,
        mode: str = "hybrid",
        top_k: int = 5,
        enable_filtering: bool = True,
    ) -> Dict[str, ThreatIdentification]:
        """Perform threat identification across all assets in the architecture."""
        return {
            aid: self.identify_threats_for_asset(aid, mode=mode, top_k=top_k, enable_filtering=enable_filtering)
            for aid in sorted(self.analyzer.assets.keys())
        }
