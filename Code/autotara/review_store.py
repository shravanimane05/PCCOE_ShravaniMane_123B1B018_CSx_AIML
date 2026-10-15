"""Human review workflow state for AutoTARA AI.

Tracks per-finding review decisions and an append-only audit log, and persists
them to a local JSON file so reviewer actions survive across sessions.
Risk acceptance always remains with the human reviewer.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import json

from autotara.config import get_config


DECISION_STATUSES = ["Pending", "Proposed", "Accepted", "Edited", "Rejected", "Needs Info"]

DECISION_COLORS = {
    "Pending": "#78909c",
    "Proposed": "#42a5f5",
    "Accepted": "#4caf50",
    "Edited": "#ffb300",
    "Rejected": "#f44336",
    "Needs Info": "#ab47bc",
}

TERMINAL_STATUSES = ("Accepted", "Edited", "Rejected")

ROLE_PERMISSIONS = {
    "Engineer": ["view", "edit", "propose", "export"],
    "Reviewer": ["view", "edit", "propose", "accept", "reject", "export"],
    "Viewer": ["view"],
}


def state_path() -> Path:
    """Path of the persisted review state file."""
    root = get_config().root_dir
    data_dir = root / "Code" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / "review_state.json"


def default_state() -> Dict[str, Any]:
    return {"decisions": {}, "audit": [], "report_approved": None}


def load_state(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load persisted review state; returns a default state when unavailable."""
    target = path or state_path()
    if not target.exists():
        return default_state()
    try:
        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return default_state()
    state = default_state()
    state.update({k: v for k, v in data.items() if k in state})
    return state


def save_state(state: Dict[str, Any], path: Optional[Path] = None) -> Path:
    """Persist review state atomically enough for local single-user use."""
    target = path or state_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    tmp.replace(target)
    return target


def can(role: str, action: str) -> bool:
    """Check whether a demo role is permitted to perform an action."""
    return action in ROLE_PERMISSIONS.get(role, ["view"])


def log_event(
    state: Dict[str, Any],
    action: str,
    detail: str,
    actor: str,
    role: str,
    persist: bool = True,
) -> Dict[str, Any]:
    """Append an audit entry for a consequential workspace action."""
    entry = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "actor": actor or "Unattributed",
        "role": role,
        "action": action,
        "detail": detail,
    }
    state.setdefault("audit", []).append(entry)
    if persist:
        save_state(state)
    return entry


def set_decision(
    state: Dict[str, Any],
    finding_key: str,
    finding_label: str,
    status: str,
    comment: str,
    actor: str,
    role: str,
    persist: bool = True,
) -> Dict[str, Any]:
    """Record a human review decision for a single TARA finding."""
    if status not in DECISION_STATUSES:
        raise ValueError(f"Unknown decision status '{status}'.")

    entry = {
        "status": status,
        "comment": comment,
        "reviewer": actor or "Unattributed",
        "role": role,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "finding": finding_label,
    }
    state.setdefault("decisions", {})[finding_key] = entry
    log_event(
        state,
        action=f"Decision: {status}",
        detail=f"{finding_label} -> {status}"
        + (f" | {comment}" if comment else ""),
        actor=actor,
        role=role,
        persist=False,
    )
    if persist:
        save_state(state)
    return entry


def get_decision(state: Dict[str, Any], finding_key: str) -> Dict[str, Any]:
    """Return the recorded decision for a finding, defaulting to Pending."""
    stored = state.get("decisions", {}).get(finding_key)
    if stored:
        return stored
    return {
        "status": "Pending",
        "comment": "",
        "reviewer": "",
        "role": "",
        "timestamp": "",
        "finding": finding_key,
    }


def summarize_decisions(state: Dict[str, Any], finding_keys: List[str]) -> Dict[str, int]:
    """Count findings per decision status, including unreviewed findings."""
    counts = {status: 0 for status in DECISION_STATUSES}
    decisions = state.get("decisions", {})
    for key in finding_keys:
        status = decisions.get(key, {}).get("status", "Pending")
        counts[status] = counts.get(status, 0) + 1
    return counts


def set_report_approval(
    state: Dict[str, Any],
    approved: bool,
    actor: str,
    role: str,
    detail: str = "",
) -> None:
    """Record the final report approval decision (reviewer-owned)."""
    state["report_approved"] = {
        "approved": approved,
        "reviewer": actor or "Unattributed",
        "role": role,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "detail": detail,
    }
    log_event(
        state,
        action="Report approved" if approved else "Report approval withdrawn",
        detail=detail,
        actor=actor,
        role=role,
    )
