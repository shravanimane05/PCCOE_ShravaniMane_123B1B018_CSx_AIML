"""Explainability support for AutoTARA AI.

Builds deterministic "Why this threat?" explanation cards from asset context,
retrieval evidence, and controlled threat-knowledge metadata. An optional
locally hosted LLM narrative can be generated from the configured prompt
template; the deterministic card remains the authoritative evidence record.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from autotara.architecture_analyzer import ArchitectureAnalyzer, AttackSurfaceContext
from autotara.config import get_config
from autotara.data_loader import DataLoader
from autotara.retrieval.base import RetrievalResult


CONFIDENCE_NOTE = """\
This is a prototype, evidence-grounded explanation. It does not constitute an \
autonomous risk decision; a qualified cybersecurity engineer must review and \
approve every recommendation before it enters the TARA work product."""


@dataclass
class ExplanationCard:
    """Structured, reviewable explanation for a single retrieved threat."""

    asset_id: str
    asset_name: str
    asset_type: str
    asset_category: str
    asset_description: str
    hosted_components: List[Dict[str, Any]]
    interfaces: List[Dict[str, Any]]
    trust_boundaries: List[Dict[str, Any]]
    pattern_id: str
    pattern_title: str
    stride_category: str
    attack_surface: str
    threat_scenario: str
    damage_scenario: str
    pattern_owner: str
    pattern_version: str
    last_review_date: str
    next_review_date: str
    freshness_status: str
    source_note: str
    suggested_control_ids: List[str]
    query_used: str
    retrieval_mode: str
    rank: int
    score: float
    normalized_score: float
    confidence_label: str
    matched_snippet: str
    fallback_note: Optional[str]
    baseline_version: str
    filtering_enabled: bool
    assumptions: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    confidence_notes: List[str] = field(default_factory=list)
    alternatives: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset": {
                "id": self.asset_id,
                "name": self.asset_name,
                "type": self.asset_type,
                "category": self.asset_category,
                "description": self.asset_description,
                "hosted_components": self.hosted_components,
            },
            "exposed_interfaces": self.interfaces,
            "trust_boundaries": self.trust_boundaries,
            "matched_pattern": {
                "id": self.pattern_id,
                "title": self.pattern_title,
                "stride_category": self.stride_category,
                "attack_surface": self.attack_surface,
                "threat_scenario": self.threat_scenario,
                "damage_scenario": self.damage_scenario,
                "owner": self.pattern_owner,
                "version": self.pattern_version,
                "last_review_date": self.last_review_date,
                "next_review_date": self.next_review_date,
                "freshness_status": self.freshness_status,
                "source_note": self.source_note,
                "suggested_control_ids": self.suggested_control_ids,
            },
            "retrieval_evidence": {
                "query_used": self.query_used,
                "retrieval_mode": self.retrieval_mode,
                "rank": self.rank,
                "score": round(float(self.score), 4),
                "normalized_score": round(float(self.normalized_score), 4),
                "confidence_label": self.confidence_label,
                "matched_snippet": self.matched_snippet,
                "fallback_note": self.fallback_note,
                "baseline_version": self.baseline_version,
                "filtering_enabled": self.filtering_enabled,
            },
            "assumptions": self.assumptions,
            "confidence_and_limitations": {
                "confidence_notes": self.confidence_notes,
                "limitations": self.limitations,
                "note": CONFIDENCE_NOTE,
            },
            "alternative_mitigations": self.alternatives,
        }


def _confidence_label(normalized: float) -> str:
    if normalized >= 0.75:
        return "High"
    if normalized >= 0.45:
        return "Medium"
    return "Low"


def build_explanation_card(
    context: AttackSurfaceContext,
    result: RetrievalResult,
    analyzer: ArchitectureAnalyzer,
    all_results: Optional[List[RetrievalResult]] = None,
    loader: Optional[DataLoader] = None,
    baseline_version: str = "v1",
    filtering_enabled: bool = True,
    query_used: Optional[str] = None,
) -> ExplanationCard:
    """Build a deterministic explanation card for one retrieval result."""
    dl = loader or DataLoader()
    patterns = {p["id"]: p for p in dl.load_threat_patterns()}
    pattern = patterns.get(result.pattern_id, {})

    interfaces: List[Dict[str, Any]] = []
    for iface_id in context.interface_ids:
        iface = analyzer.get_interface(iface_id)
        if not iface:
            continue
        source = analyzer.get_component(iface.get("source_component_id", ""))
        target = analyzer.get_component(iface.get("target_component_id", ""))
        interfaces.append(
            {
                "id": iface["id"],
                "name": iface.get("name", ""),
                "protocol": iface.get("protocol", ""),
                "from": source.get("name", "") if source else "",
                "to": target.get("name", "") if target else "",
                "trust_boundary_id": iface.get("trust_boundary_id", ""),
                "description": iface.get("description", ""),
            }
        )

    boundaries: List[Dict[str, Any]] = []
    for tb_id in context.trust_boundary_ids:
        tb = analyzer.trust_boundaries.get(tb_id, {})
        from_zone = analyzer.trust_zones.get(tb.get("from_zone_id", ""), {})
        to_zone = analyzer.trust_zones.get(tb.get("to_zone_id", ""), {})
        boundaries.append(
            {
                "id": tb_id,
                "name": tb.get("name", ""),
                "crossing": (
                    f"{from_zone.get('name', '?')} ({from_zone.get('trust_level', '?')}) "
                    f"-> {to_zone.get('name', '?')} ({to_zone.get('trust_level', '?')})"
                ),
            }
        )

    components = []
    for comp_id in context.hosted_components:
        comp = analyzer.get_component(comp_id) or {}
        components.append({"id": comp_id, "name": comp.get("name", comp_id)})

    results = all_results or [result]
    top_score = max((abs(r.score) for r in results), default=0.0)
    normalized = (abs(result.score) / top_score) if top_score > 0 else 0.0
    confidence = _confidence_label(normalized)

    alternatives = [
        {
            "pattern_id": r.pattern_id,
            "title": r.title,
            "score": round(float(r.score), 4),
            "rank": r.rank,
            "trust_boundary": r.trust_boundary,
            "note": "Candidate from the same retrieval run; review if the primary match is rejected.",
        }
        for r in results
        if r.pattern_id != result.pattern_id
    ]

    assumptions = [
        f"Architecture baseline '{analyzer.name}' (v{analyzer.version}, selected as {baseline_version}) "
        "is approved and complete for this analysis.",
        "The retrieved pattern comes from the controlled, owned threat knowledge base; no external or "
        "proprietary threat content was introduced.",
        (
            "Candidate filtering by trust boundary and asset type was applied before ranking."
            if filtering_enabled
            else "Candidate filtering was disabled; unfiltered results may include out-of-scope patterns."
        ),
        "Risk, mitigation, and requirement values are prototype drafts pending qualified-engineer review.",
    ]

    limitations = [
        "Prototype retrieval and scoring model; not a certified ISO/SAE 21434 assessment method.",
        "Only approved knowledge-base patterns can be recommended; novel or asset-specific threats may be absent.",
        "The explanation is derived from retrieved evidence and architecture context, not from live vulnerability data.",
    ]

    confidence_notes = [
        f"Relative match strength {normalized:.0%} against the strongest candidate in this run "
        f"-> {confidence} confidence.",
        f"Ranked #{result.rank} of {len(results)} candidate(s) using '{result.retrieval_mode}' retrieval.",
    ]
    if result.fallback_note:
        confidence_notes.append(result.fallback_note)
    freshness = pattern.get("freshness_status", "Unknown")
    if freshness == "Outdated":
        confidence_notes.append(
            "The matched pattern is flagged Outdated; treat currency of the evidence as low until re-reviewed."
        )
    elif freshness == "Review Due":
        confidence_notes.append("The matched pattern is Review Due; confirm currency with the pattern owner.")

    return ExplanationCard(
        asset_id=context.asset_id,
        asset_name=context.asset_name,
        asset_type=context.asset_type,
        asset_category=context.asset_category,
        asset_description=context.description,
        hosted_components=components,
        interfaces=interfaces,
        trust_boundaries=boundaries,
        pattern_id=result.pattern_id,
        pattern_title=pattern.get("title", result.title or ""),
        stride_category=pattern.get("stride_category", ""),
        attack_surface=pattern.get("attack_surface", ""),
        threat_scenario=pattern.get("threat_scenario", ""),
        damage_scenario=pattern.get("damage_scenario", ""),
        pattern_owner=pattern.get("owner", ""),
        pattern_version=pattern.get("version", ""),
        last_review_date=pattern.get("last_review_date", ""),
        next_review_date=pattern.get("next_review_date", ""),
        freshness_status=freshness,
        source_note=pattern.get("source_note", ""),
        suggested_control_ids=list(pattern.get("suggested_control_ids", [])),
        query_used=query_used or context.build_query(),
        retrieval_mode=result.retrieval_mode,
        rank=result.rank,
        score=result.score,
        normalized_score=normalized,
        confidence_label=confidence,
        matched_snippet=result.matched_snippet,
        fallback_note=result.fallback_note,
        baseline_version=baseline_version,
        filtering_enabled=filtering_enabled,
        assumptions=assumptions,
        limitations=limitations,
        confidence_notes=confidence_notes,
        alternatives=alternatives,
    )


def load_prompt_template(name: str = "explanation_prompt_v1.txt") -> Optional[str]:
    """Load a prompt template from Model_Prompts_Config/prompts when available."""
    root = get_config().root_dir
    candidates = sorted(root.glob("**/Model_Prompts_Config/prompts/" + name))
    if not candidates:
        return None
    return candidates[0].read_text(encoding="utf-8")


def render_prompt(card: ExplanationCard, template: str) -> str:
    """Fill the explanation prompt template with card evidence."""
    boundary = ", ".join(f"{b['id']} {b['name']}" for b in card.trust_boundaries) or "n/a"
    protocols = ", ".join(i["protocol"] for i in card.interfaces if i["protocol"]) or "n/a"
    controls = ", ".join(card.suggested_control_ids) or "none"
    replacements = {
        "{asset_name}": card.asset_name,
        "{asset_type}": card.asset_type,
        "{protocols}": protocols,
        "{trust_boundary}": boundary,
        "{attack_surface}": card.attack_surface or card.asset_description,
        "{pattern_id}": card.pattern_id,
        "{pattern_title}": card.pattern_title,
        "{pattern_description}": card.matched_snippet,
        "{threat_scenario}": card.threat_scenario,
        "{damage_scenario}": card.damage_scenario,
        "{suggested_controls}": controls,
    }
    filled = template
    for key, value in replacements.items():
        filled = filled.replace(key, value)
    return filled


def generate_llm_explanation(card: ExplanationCard, timeout: Optional[int] = None) -> str:
    """Request an optional narrative explanation from the configured local LLM.

    Raises RuntimeError when the LLM is disabled, unreachable, or returns nothing.
    """
    import requests

    cfg = get_config().llm_config
    if not cfg.get("enabled", False):
        raise RuntimeError("LLM assistance is disabled in Model_Prompts_Config/config.yaml (llm.enabled=false).")

    template = load_prompt_template()
    if not template:
        raise RuntimeError("Explanation prompt template not found under Model_Prompts_Config/prompts.")

    prompt = render_prompt(card, template)
    url = cfg.get("base_url", "http://localhost:11434").rstrip("/") + "/api/generate"
    payload = {
        "model": cfg.get("model", "llama3.2:3b"),
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": cfg.get("temperature", 0.0)},
    }
    response = requests.post(
        url,
        json=payload,
        timeout=timeout or cfg.get("timeout_seconds", 30),
    )
    response.raise_for_status()
    data = response.json()
    text = (data.get("response") or "").strip()
    if not text:
        raise RuntimeError("The local LLM returned an empty response.")
    return text
