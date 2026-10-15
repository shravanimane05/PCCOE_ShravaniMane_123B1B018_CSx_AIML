"""Base data structures and candidate filtering for AutoTARA AI retrieval."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class RetrievalResult:
    """Carries threat retrieval outcome.

    Rule 5: Every retrieval result carries: pattern ID, score, rank, retrieval mode, matched snippet.
    The explainer will reuse this object in Phase 3.
    """
    pattern_id: str
    score: float
    rank: int
    retrieval_mode: str
    matched_snippet: str
    title: Optional[str] = None
    trust_boundary: Optional[str] = None
    applicable_asset_types: List[str] = field(default_factory=list)
    fallback_note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "score": round(float(self.score), 4),
            "rank": self.rank,
            "retrieval_mode": self.retrieval_mode,
            "matched_snippet": self.matched_snippet,
            "title": self.title,
            "trust_boundary": self.trust_boundary,
            "applicable_asset_types": self.applicable_asset_types,
            "fallback_note": self.fallback_note,
        }


def build_pattern_document(pattern: Dict[str, Any]) -> str:
    """Construct searchable text representation of a threat pattern for indexers."""
    parts = [
        pattern.get("title", ""),
        pattern.get("description", ""),
        pattern.get("threat_scenario", ""),
        pattern.get("damage_scenario", ""),
        pattern.get("attack_surface", ""),
        f"STRIDE: {pattern.get('stride_category', '')}",
        f"Trust Boundary: {pattern.get('trust_boundary', '')}",
        f"Asset Types: {', '.join(pattern.get('applicable_asset_types', []))}",
        f"Interfaces: {', '.join(pattern.get('interface_types', []))}",
    ]
    return " \n".join(p for p in parts if p.strip())


def filter_candidates(
    patterns: List[Dict[str, Any]],
    asset_type: Optional[str] = None,
    trust_boundary_ids: Optional[List[str]] = None,
    baseline_version: str = "v1",
    enable_filtering: bool = True,
) -> List[Dict[str, Any]]:
    """Filter threat pattern candidates before ranking.

    Rule 2:
    - Filter candidates by trust boundary ID and asset type BEFORE ranking.
    - Flag `enable_filtering` to turn filtering off so evaluation can measure its effect.
    - Patterns referencing TB-05 must NEVER appear for the v1 baseline.
    """
    candidates = []
    is_v1 = baseline_version in ("v1", "1", "1.0")
    tb_filter_set = set(trust_boundary_ids) if trust_boundary_ids else set()

    for p in patterns:
        tb = p.get("trust_boundary")

        # In v1 baseline, TB-05 physically does not exist in the architecture
        if is_v1 and tb == "TB-05":
            continue

        if not enable_filtering:
            candidates.append(p)
            continue

        # If filtering enabled:
        # Check trust boundary match
        if tb_filter_set and tb not in tb_filter_set:
            continue

        # Check asset type match
        if asset_type:
            p_asset_types = p.get("applicable_asset_types", [])
            if asset_type not in p_asset_types:
                continue

        candidates.append(p)

    return candidates
