"""Reusable workspace components shared across AutoTARA AI views."""

from typing import Any, Dict, List, Optional, Sequence
import pandas as pd
import streamlit as st

from autotara.ui import state, theme


def page(title: str, subtitle: str) -> None:
    """Render the standard page header."""
    theme.hero(title, subtitle)
    st.write("")


def dataframe(rows: Sequence[Dict[str, Any]], columns: Optional[List[str]] = None, empty: str = "No records.") -> None:
    """Render a list of dicts as a stretched, index-free dataframe."""
    if not rows:
        st.info(empty)
        return
    frame = pd.DataFrame(list(rows))
    if columns:
        for col in columns:
            if col not in frame.columns:
                frame[col] = ""
        frame = frame[columns]
    st.dataframe(frame, width="stretch", hide_index=True)


def asset_options(analyzer) -> List[tuple]:
    """Build (label, asset_id) options for the active baseline."""
    options = []
    for asset_id in sorted(analyzer.assets.keys()):
        asset = analyzer.assets[asset_id]
        options.append((f"{asset_id} — {asset['name']} ({asset.get('type', '')})", asset_id))
    return options


def asset_select(analyzer, label: str = "Asset", key: str = "sel_asset") -> str:
    """Asset picker bound to session state."""
    options = asset_options(analyzer)
    default_ids = [o[1] for o in options]
    current = st.session_state.get(key)
    index = default_ids.index(current) if current in default_ids else 0
    selected = st.selectbox(
        label,
        options=[o[1] for o in options],
        index=index,
        format_func=lambda aid: next(o[0] for o in options if o[1] == aid),
        key=key,
        help="Cybersecurity-relevant asset from the selected architecture baseline.",
    )
    st.session_state["focus_asset"] = selected
    return selected


def finding_format(row: Dict[str, Any]) -> str:
    """Human-readable label for a finding option."""
    return f"{row['asset_id']} · {row['threat_id']} — {row['threat_title']}"


def finding_select(
    rows: Sequence[Dict[str, Any]],
    label: str = "Finding",
    key: str = "sel_finding",
    help: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Picker over recorded findings; returns the selected finding dict."""
    if not rows:
        st.info("No findings recorded yet. Run a threat analysis first.")
        return None
    keys = [r["finding_key"] if "finding_key" in r else state.finding_key(r["asset_id"], r["threat_id"]) for r in rows]
    current = st.session_state.get(key)
    if current not in keys:
        focus = st.session_state.get("focus_threat", "")
        focus_keys = [k for k, r in zip(keys, rows) if r["threat_id"] == focus]
        current = focus_keys[0] if focus_keys else keys[0]
    index = keys.index(current)
    chosen = st.selectbox(
        label,
        options=keys,
        index=index,
        format_func=lambda k: finding_format(rows[keys.index(k)]),
        key=key,
        help=help,
    )
    selected = rows[keys.index(chosen)]
    st.session_state["focus_threat"] = selected["threat_id"]
    return selected


def status_pill(status: str) -> str:
    """Colored pill for a risk / freshness / decision status."""
    return theme.pill(status)


def callout(kind: str, title: str, body: str) -> None:
    st.markdown(theme.callout(kind, title, body), unsafe_allow_html=True)


def note(text: str) -> None:
    st.markdown(f'<div class="at-note">{theme.esc(text)}</div>', unsafe_allow_html=True)


def permission_hint(action: str) -> str:
    """Explain a permission block for the active demo role."""
    return (
        f"Your demo role ({state.role()}) is not permitted to {action}. "
        "Switch role in the sidebar (Reviewer can accept or reject findings)."
    )
