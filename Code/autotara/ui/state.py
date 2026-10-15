"""Session state and cached engine access for the AutoTARA AI UI."""

from typing import Any, Dict, List, Optional
from pathlib import Path
import streamlit as st

from autotara.architecture_analyzer import ArchitectureAnalyzer
from autotara.change_impact import ChangeImpactReport, build_change_impact
from autotara.config import get_config
from autotara.data_loader import DataLoader
from autotara.mitigation_engine import MitigationEngine
from autotara.retrieval.index_builder import IndexBuilder
from autotara.review_store import (
    DECISION_STATUSES,
    can,
    get_decision,
    load_state,
    log_event,
    save_state,
    set_decision,
    summarize_decisions,
)
from autotara.threat_engine import ThreatEngine
from autotara.traceability import TraceabilityGraph
from autotara.validation import DataValidator


BASELINE_LABELS = {
    "v1": "Baseline v1 — Connected Vehicle Telematics",
    "v2": "Baseline v2 — Bluetooth Diagnostic Adapter",
}

SESSION_DEFAULTS: Dict[str, Any] = {
    "baseline": "v1",
    "role": "Reviewer",
    "actor": "",
    "findings": {},
    "risk": {},
    "analysis_meta": {},
    "focus_threat": "",
    "focus_asset": "",
    "acknowledged_changes": [],
    "llm_note": "",
}


def init_session() -> None:
    """Initialize session defaults and hydrate persisted review state."""
    for key, value in SESSION_DEFAULTS.items():
        if key not in st.session_state:
            if isinstance(value, (dict, list)):
                st.session_state[key] = value.copy()
            else:
                st.session_state[key] = value
    if "review" not in st.session_state:
        st.session_state["review"] = load_state()


def actor() -> str:
    return st.session_state.get("actor", "") or "Unattributed"


def role() -> str:
    return st.session_state.get("role", "Viewer")


def baseline() -> str:
    return st.session_state.get("baseline", "v1")


def can_act(action: str) -> bool:
    """Permission gate for the active demo role."""
    return can(role(), action)


def review_state() -> Dict[str, Any]:
    return st.session_state["review"]


def persist_review() -> Path:
    return save_state(review_state())


def log(action: str, detail: str) -> None:
    """Append and persist an audit entry from the UI."""
    log_event(review_state(), action=action, detail=detail, actor=actor(), role=role())
    persist_review()


def record_decision(finding_key: str, finding_label: str, status: str, comment: str) -> None:
    """Store a human review decision and refresh the audit trail."""
    set_decision(
        review_state(),
        finding_key=finding_key,
        finding_label=finding_label,
        status=status,
        comment=comment,
        actor=actor(),
        role=role(),
    )
    persist_review()


def decision_for(finding_key: str) -> Dict[str, Any]:
    return get_decision(review_state(), finding_key)


def decision_summary(finding_keys: List[str]) -> Dict[str, int]:
    return summarize_decisions(review_state(), finding_keys)


# --- Cached engine access -------------------------------------------------


@st.cache_resource(show_spinner=False)
def get_loader() -> DataLoader:
    return DataLoader()


@st.cache_resource(show_spinner=False)
def get_config_obj():
    return get_config()


@st.cache_resource(show_spinner=False)
def get_analyzer(version: str) -> ArchitectureAnalyzer:
    return ArchitectureAnalyzer.from_loader(get_loader(), version=version)


@st.cache_resource(show_spinner=False)
def get_index_builder() -> IndexBuilder:
    return IndexBuilder(loader=get_loader())


@st.cache_resource(show_spinner=False)
def get_threat_engine(version: str) -> ThreatEngine:
    return ThreatEngine(
        analyzer=get_analyzer(version),
        index_builder=get_index_builder(),
        loader=get_loader(),
    )


@st.cache_resource(show_spinner=False)
def get_mitigation_engine() -> MitigationEngine:
    return MitigationEngine(loader=get_loader())


@st.cache_resource(show_spinner=False)
def get_traceability(version: str) -> TraceabilityGraph:
    return TraceabilityGraph(loader=get_loader(), analyzer=get_analyzer(version))


@st.cache_resource(show_spinner=False)
def get_validation_report():
    return DataValidator().validate_all()


@st.cache_resource(show_spinner=False)
def get_change_impact() -> ChangeImpactReport:
    report = build_change_impact(loader=get_loader(), base_version="v1", target_version="v2")
    for pattern in get_loader().load_threat_patterns():
        match = next((t for t in report.impacted_threats if t["id"] == pattern["id"]), None)
        if match:
            match["freshness_status"] = pattern.get("freshness_status", "")
    return report


# --- Findings workspace ---------------------------------------------------


def finding_key(asset_id: str, threat_id: str) -> str:
    return f"{asset_id}:{threat_id}"


def record_findings(asset_id: str, asset_name: str, findings: List[Dict[str, Any]], meta: Dict[str, Any]) -> None:
    """Persist retrieval outcomes for an asset as reviewable findings."""
    st.session_state["findings"][asset_id] = findings
    st.session_state["analysis_meta"][asset_id] = meta
    st.session_state["focus_asset"] = asset_id
    if findings:
        st.session_state["focus_threat"] = findings[0].get("threat_id", "")


def all_findings() -> List[Dict[str, Any]]:
    """Flatten findings across all analyzed assets."""
    rows: List[Dict[str, Any]] = []
    for asset_id in sorted(st.session_state["findings"].keys()):
        rows.extend(st.session_state["findings"][asset_id])
    return rows


def risk_for(threat_id: str) -> Optional[Dict[str, Any]]:
    return st.session_state["risk"].get(threat_id)


def store_risk(threat_id: str, impact: int, feasibility: int, assessment: Dict[str, Any]) -> None:
    st.session_state["risk"][threat_id] = {
        "impact": impact,
        "attack_feasibility": feasibility,
        "score": assessment["score"],
        "band": assessment["band"],
        "color": assessment["color"],
        "impact_label": assessment["impact_label"],
        "feasibility_label": assessment["feasibility_label"],
    }


def clear_analysis(reason: str) -> None:
    """Drop baseline-dependent findings and log the reset."""
    if st.session_state["findings"] or st.session_state["risk"]:
        st.session_state["findings"] = {}
        st.session_state["analysis_meta"] = {}
        st.session_state["focus_threat"] = ""
        st.session_state["focus_asset"] = ""
        log("Baseline changed", reason)


def merged_findings() -> List[Dict[str, Any]]:
    """Findings enriched with risk assessment and review decision state."""
    merged: List[Dict[str, Any]] = []
    for row in all_findings():
        item = dict(row)
        risk = risk_for(item["threat_id"])
        if risk:
            item.update(
                {
                    "impact": risk["impact"],
                    "attack_feasibility": risk["attack_feasibility"],
                    "risk_score": risk["score"],
                    "risk_band": risk["band"],
                }
            )
        else:
            item.update(
                {
                    "impact": "",
                    "attack_feasibility": "",
                    "risk_score": "",
                    "risk_band": "",
                }
            )
        key = finding_key(item["asset_id"], item["threat_id"])
        decision = decision_for(key)
        item.update(
            {
                "finding_key": key,
                "decision_status": decision.get("status", "Pending"),
                "decision_reviewer": decision.get("reviewer", ""),
                "decision_comment": decision.get("comment", ""),
                "decision_timestamp": decision.get("timestamp", ""),
            }
        )
        merged.append(item)
    return merged
