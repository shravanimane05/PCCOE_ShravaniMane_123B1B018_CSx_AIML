"""Visual theme, CSS, and HTML helpers for the AutoTARA AI workspace."""

from typing import Dict, List, Optional, Sequence
import html

ACCENT = "#4da3ff"
RISK_COLORS = {
    "Low": "#4caf50",
    "Medium": "#ff9800",
    "High": "#f44336",
    "Critical": "#9c27b0",
}

FRESHNESS_COLORS = {
    "Current": "#4caf50",
    "Review Due": "#ff9800",
    "Outdated": "#f44336",
    "Unknown": "#78909c",
}

DECISION_COLORS = {
    "Pending": "#78909c",
    "Proposed": "#42a5f5",
    "Accepted": "#4caf50",
    "Edited": "#ffb300",
    "Rejected": "#f44336",
    "Needs Info": "#ab47bc",
}

STATUS_COLOR = {
    **RISK_COLORS,
    **FRESHNESS_COLORS,
    **DECISION_COLORS,
    "PASS": "#4caf50",
    "FAIL": "#f44336",
    "Requires reassessment": "#ff9800",
    "AVAILABLE": "#4caf50",
    "NOT_RUN": "#78909c",
    "High": "#f44336",
    "Medium": "#ff9800",
    "Low": "#4caf50",
}

_CSS = """
<style>
.at-hero {
  padding: 1.1rem 1.3rem;
  border-radius: 14px;
  background: linear-gradient(115deg, #101828 0%, #14213a 55%, #16233f 100%);
  border: 1px solid #26344f;
  margin-bottom: 0.4rem;
}
.at-hero h1 { margin: 0 0 0.25rem 0; font-size: 1.65rem; color: #eef3fc; }
.at-hero p { margin: 0; color: #a9b8d4; font-size: 0.92rem; }
.at-kpi {
  border: 1px solid #27334c;
  border-left: 4px solid {accent};
  background: #131a2a;
  border-radius: 10px;
  padding: 0.7rem 0.85rem;
  min-height: 92px;
}
.at-kpi .k-label { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.09em; color: #8fa1c0; }
.at-kpi .k-value { font-size: 1.5rem; font-weight: 700; color: #e9eef8; line-height: 1.25; }
.at-kpi .k-sub { font-size: 0.74rem; color: #8fa1c0; }
table.at-table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
table.at-table th {
  text-align: left; padding: 0.48rem 0.6rem; color: #9db0d2; background: #17203380;
  font-weight: 600; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.06em;
  border-bottom: 1px solid #2a3650;
}
table.at-table td { padding: 0.48rem 0.6rem; border-bottom: 1px solid #1f2a40; vertical-align: top; color: #dce4f2; }
table.at-table tr:hover td { background: #18213480; }
.at-pill {
  display: inline-block; padding: 0.08rem 0.55rem; border-radius: 999px;
  font-size: 0.72rem; font-weight: 700; color: #0b0f17; white-space: nowrap;
}
.at-pill-outline {
  display: inline-block; padding: 0.06rem 0.5rem; border-radius: 999px;
  font-size: 0.72rem; font-weight: 700; color: {accent};
  border: 1px solid {accent}; background: #101a2c; white-space: nowrap;
}
.at-callout { border-radius: 10px; padding: 0.75rem 0.95rem; border: 1px solid; font-size: 0.86rem; margin: 0.4rem 0 0.8rem 0; }
.at-callout .c-title { font-weight: 700; margin-bottom: 0.2rem; }
.at-scenario {
  background: #101728; border: 1px solid #243150; border-radius: 8px;
  padding: 0.7rem 0.85rem; white-space: pre-wrap; font-size: 0.85rem; color: #d7e0f0;
}
.at-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.78rem; color: #9ecbff; word-break: break-all; }
.at-section { margin-top: 1.1rem; }
.at-section h3 { margin: 0 0 0.35rem 0; color: #e6ecf8; font-size: 1.05rem; }
.at-caption { color: #93a4c3; font-size: 0.82rem; margin-bottom: 0.5rem; }
.at-kv { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
.at-kv td { padding: 0.35rem 0.5rem; border-bottom: 1px solid #1f2a40; }
.at-kv td:first-child { color: #93a4c3; width: 34%; }
.at-kv td:last-child { color: #dce4f2; }
.at-chain { display: flex; gap: 0.55rem; overflow-x: auto; padding: 0.4rem 0 0.8rem 0; }
.at-chain-col { min-width: 150px; flex: 1; }
.at-chain-col .col-title { font-size: 0.66rem; text-transform: uppercase; letter-spacing: 0.08em; color: #8fa1c0; margin-bottom: 0.3rem; }
.at-node {
  background: #141c2e; border: 1px solid #2a3650;
  border-left: 3px solid {accent};
  border-radius: 8px; padding: 0.42rem 0.55rem; margin-bottom: 0.35rem; font-size: 0.78rem; color: #dce4f2;
}
.at-node .n-id { color: #9ecbff; font-weight: 700; font-size: 0.72rem; }
.at-matrix { border-collapse: separate; border-spacing: 3px; font-size: 0.78rem; }
.at-matrix th { color: #93a4c3; font-weight: 600; padding: 0.2rem 0.4rem; font-size: 0.7rem; }
.at-matrix td.cell { width: 56px; height: 42px; text-align: center; border-radius: 7px; font-weight: 700; color: #0b0f17; }
.at-matrix td.cell.selected { outline: 3px solid #eef3fc; outline-offset: 1px; }
.at-matrix td.axis { background: transparent; color: #93a4c3; text-align: center; font-weight: 600; }
.at-note { font-size: 0.78rem; color: #8fa1c0; }
</style>
"""


def inject_css() -> None:
    """Inject the workspace stylesheet once per Streamlit run."""
    import streamlit as st

    st.markdown(_CSS.replace("{accent}", ACCENT), unsafe_allow_html=True)


def esc(value: object) -> str:
    """HTML-escape a value for safe embedding."""
    return html.escape("" if value is None else str(value))


_HTML_PREFIXES = ("<span", "<div", "<table", "<b>", "<strong", "<a ", "<br", "<ul", "<li", "<code", "<p>")


def _looks_html(value: object) -> bool:
    """Detect pre-rendered HTML cell content so it is not escaped twice."""
    if not isinstance(value, str):
        return False
    return value.lstrip().startswith(_HTML_PREFIXES)


def color_for(status: str) -> str:
    """Resolve a display color for a known status label."""
    return STATUS_COLOR.get(status, "#78909c")


def pill(text: str, color: Optional[str] = None) -> str:
    """Render a filled status pill."""
    shade = color or color_for(text)
    return f'<span class="at-pill" style="background:{shade}">{esc(text)}</span>'


def outline_pill(text: str, color: Optional[str] = None) -> str:
    """Render an outlined pill."""
    shade = color or ACCENT
    return f'<span class="at-pill-outline" style="color:{shade};border-color:{shade}">{esc(text)}</span>'


def kpi_card(label: str, value: object, sub: str = "", color: str = ACCENT) -> str:
    """Render a KPI card as HTML."""
    return (
        f'<div class="at-kpi" style="border-left-color:{color}">'
        f'<div class="k-label">{esc(label)}</div>'
        f'<div class="k-value">{esc(value)}</div>'
        f'<div class="k-sub">{esc(sub)}</div></div>'
    )


def html_table(headers: Sequence[str], rows: Sequence[Sequence[object]], caption: str = "") -> str:
    """Render an HTML table. Cell values may contain pre-built HTML (pills)."""
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = []
    for row in rows:
        cells = "".join(f"<td>{cell if _looks_html(cell) else esc(cell)}</td>" for cell in row)
        body.append(f"<tr>{cells}</tr>")
    caption_html = f'<div class="at-caption">{esc(caption)}</div>' if caption else ""
    return f'{caption_html}<table class="at-table"><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table>'


def kv_table(pairs: Sequence[tuple]) -> str:
    """Render a two-column key/value table."""
    rows = "".join(
        f"<tr><td>{esc(key)}</td><td>{value if _looks_html(value) else esc(value)}</td></tr>"
        for key, value in pairs
    )
    return f'<table class="at-kv">{rows}</table>'


def callout(kind: str, title: str, body: str) -> str:
    """Render an informational callout box."""
    palette = {
        "info": ("#16324f", "#2f6fb0", "#bcd8f7"),
        "success": ("#12331f", "#2f8f4e", "#bfe8cd"),
        "warning": ("#3a2a10", "#c78a1d", "#f4dcb4"),
        "danger": ("#3a1620", "#c0392b", "#f6c9c4"),
        "muted": ("#161d2e", "#3b4a68", "#b8c4da"),
    }
    background, border, text = palette.get(kind, palette["info"])
    return (
        f'<div class="at-callout" style="background:{background};border-color:{border};color:{text}">'
        f'<div class="c-title">{esc(title)}</div><div>{body}</div></div>'
    )


def scenario_box(text: str) -> str:
    """Render a scenario / long-text block."""
    return f'<div class="at-scenario">{esc(text)}</div>'


def mono(text: str) -> str:
    """Render monospace evidence text (retrieval queries, prompts)."""
    return f'<span class="at-mono">{esc(text)}</span>'


def section(title: str, caption: str = "") -> None:
    """Render a section heading with optional caption."""
    import streamlit as st

    caption_html = f'<div class="at-caption">{esc(caption)}</div>' if caption else ""
    st.markdown(f'<div class="at-section"><h3>{esc(title)}</h3>{caption_html}</div>', unsafe_allow_html=True)


def kpi_row(items: List[tuple], columns: int = 4) -> None:
    """Render a row of KPI cards. Each item is (label, value, sub, color)."""
    import streamlit as st

    for start in range(0, len(items), columns):
        chunk = items[start : start + columns]
        cols = st.columns(columns)
        for col, item in zip(cols, chunk):
            label, value, sub = item[0], item[1], item[2] if len(item) > 2 else ""
            color = item[3] if len(item) > 3 else ACCENT
            with col:
                st.markdown(kpi_card(label, value, sub, color), unsafe_allow_html=True)


def hero(title: str, subtitle: str) -> None:
    """Render the page hero banner."""
    import streamlit as st

    st.markdown(
        f'<div class="at-hero"><h1>{esc(title)}</h1><p>{esc(subtitle)}</p></div>',
        unsafe_allow_html=True,
    )
