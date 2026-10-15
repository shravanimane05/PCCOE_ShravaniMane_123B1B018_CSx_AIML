"""Overview / dashboard view for the AutoTARA AI workspace."""

import streamlit as st

from autotara.ui import components, state, theme


PIPELINE = [
    ("1. Architecture input", "Load a fictional baseline (JSON) or a selected sample scenario."),
    ("2. Asset & interface analysis", "Assets, interfaces, trust zones, data flows, attack surfaces."),
    ("3. Threat engine", "Matches controlled threat patterns to asset/interface context."),
    ("4. Risk engine", "Impact x Attack Feasibility with transparent prototype bands."),
    ("5. Mitigation engine", "Recommends controls and drafts cybersecurity requirements."),
    ("6. Verification assistant", "Suggests test cases for control and requirement validation."),
    ("7. Traceability view", "Asset -> interface -> threat -> risk -> control -> requirement -> test -> decision."),
    ("8. Change-impact view", "Artifacts affected by an added, removed, or modified component."),
    ("9. Report generator", "Structured CSV/JSON export gated by validation and human approval."),
]


def render() -> None:
    cfg = state.get_config_obj()
    analyzer = state.get_analyzer(state.baseline())
    loader = state.get_loader()
    topology = analyzer.summarize_topology()
    patterns = loader.load_threat_patterns()
    controls = loader.load_controls()
    requirements = loader.load_requirements()
    tests = loader.load_verification_tests()
    trace = state.get_traceability(state.baseline())
    completeness = trace.validate_completeness()
    validation = state.get_validation_report()
    findings = state.merged_findings()
    keys = [f["finding_key"] for f in findings]
    summary = state.decision_summary(keys)

    components.page(
        cfg.project_name,
        "Explainable, change-aware automotive cybersecurity Threat Analysis and Risk Assessment assistant "
        "for a fictional connected-vehicle telematics, OTA, and remote-control system.",
    )

    theme.kpi_row(
        [
            ("Assets", topology["asset_count"], "in current baseline"),
            ("Interfaces", topology["interface_count"], f"{topology['trust_boundary_count']} trust boundaries"),
            ("Threat patterns", len(patterns), "controlled knowledge base"),
            ("Controls / Requirements / Tests", f"{len(controls)} / {len(requirements)} / {len(tests)}", "fully linked"),
            ("Traceability completeness", f"{completeness.completeness_percentage:.0f}%", "threat -> test coverage"),
            ("Data validation", "PASS" if validation.is_valid else "FAIL", f"{len(validation.errors)} error(s)"),
            ("Findings recorded", len(findings), f"{summary['Accepted']} accepted, {summary['Pending']} pending"),
            ("Active role", state.role(), f"analyst: {state.actor()}"),
        ],
        columns=4,
    )

    st.markdown("")
    components.callout(
        "warning",
        "Prototype model — human decision authority retained",
        "Risk score = Impact x Attack Feasibility on a 1-5 scale using an illustrative prototype model. "
        "It is <b>not</b> an organization-approved ISO/SAE 21434 methodology, and every consequential "
        "finding requires review and approval by an authorized cybersecurity engineer. "
        "This platform never accepts risk autonomously and never exploits vulnerabilities.",
    )

    left, right = st.columns(2)

    with left:
        theme.section("Session context", "Everything below reflects the baseline selected in the sidebar.")
        st.markdown(
            theme.kv_table(
                [
                    ("Architecture baseline", f"{state.baseline()} — {analyzer.name}"),
                    ("Baseline version", analyzer.version),
                    ("Components", topology["component_count"]),
                    ("Trust zones / boundaries", f"{topology['trust_zone_count']} / {topology['trust_boundary_count']}"),
                    ("Retrieval modes ready", ", ".join(f"{k}: {v}" for k, v in state.get_index_builder().get_mode_status().items())),
                    ("Threat-knowledge anchor date", cfg.reference_date.strftime("%Y-%m-%d")),
                    ("Audit entries stored", len(state.review_state().get("audit", []))),
                ]
            ),
            unsafe_allow_html=True,
        )

        theme.section("Governance controls in force")
        st.markdown(
            theme.html_table(
                ["Control", "Applied in this workspace"],
                [
                    ["Mandatory human review", "No finding is accepted without a recorded reviewer decision."],
                    ["Evidence-based output", "Every recommendation carries context, assumptions, confidence, limitations."],
                    ["Role-based access", "Engineer proposes, Reviewer accepts/rejects, Viewer observes."],
                    ["Versioned inputs", "Architecture baselines and knowledge artifacts are versioned and dated."],
                    ["Audit log", "Recommendations, decisions, comments, and status changes are timestamped."],
                    ["Validation gate", "Report approval requires zero broken links and complete traceability."],
                ],
            ),
            unsafe_allow_html=True,
        )

    with right:
        theme.section("End-to-end workflow", "Nine guided stages from architecture input to approved report.")
        for title, body in PIPELINE:
            st.markdown(
                f'<div class="at-node"><span class="n-id">{theme.esc(title)}</span><br>{theme.esc(body)}</div>',
                unsafe_allow_html=True,
            )

    theme.section("Expected benefits", "Indicative measures tracked by the platform.")
    st.markdown(
        theme.html_table(
            ["Benefit", "Indicative measurement", "Live value"],
            [
                ["Faster TARA preparation", "Time from architecture input to reviewed TARA", f"{len(findings)} finding(s) staged"],
                ["Better asset coverage", "Confirmed assets vs manual baseline", f"{topology['asset_count']} assets analyzed"],
                ["Knowledge reuse", "Recommendations sourced from approved patterns", f"{len(patterns)} approved patterns"],
                ["Traceability completeness", "Linked assets, threats, controls, requirements, tests", f"{completeness.completeness_percentage:.0f}%"],
                ["Review quality", "Accepted / edited / rejected / pending ratios",
                 f"{summary['Accepted']} / {summary['Edited']} / {summary['Rejected']} / {summary['Pending']}"],
                ["Change responsiveness", "Artifacts identified after an architecture change",
                 f"{len(state.get_change_impact().impacted_threats)} threats flagged"],
            ],
        ),
        unsafe_allow_html=True,
    )
