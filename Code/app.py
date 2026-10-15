"""AutoTARA AI — guided automotive TARA workspace."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

CODE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = CODE_DIR.parent
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from autotara.architecture_analyzer import ArchitectureAnalyzer
from autotara.data_loader import DataLoader
from autotara.mitigation_engine import MitigationEngine
from autotara.risk_engine import RiskEngine


st.set_page_config(page_title="AutoTARA AI", page_icon="◈", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@400;500;600;700;800&display=swap');
:root{--ink:#17231e;--muted:#78857f;--line:#e7ece8;--paper:#f7f9f7;--green:#1c7355;--lime:#c9f26b;--red:#c9564f;--amber:#c48a2a}
html,body,[class*="css"]{font-family:'DM Sans',sans-serif;color:var(--ink)}
.stApp{background:#f7f9f7} section[data-testid="stSidebar"]{background:#10251e;border-right:0} section[data-testid="stSidebar"] *{color:#e7f0eb}
section[data-testid="stSidebar"] [data-testid="stRadio"] label{padding:9px 12px;border-radius:9px;font-size:14px}
section[data-testid="stSidebar"] [data-testid="stRadio"] label:hover{background:#ffffff12}
.brand{display:flex;align-items:center;gap:12px;padding:8px 2px 24px;border-bottom:1px solid #ffffff20;margin-bottom:22px}
.brand-icon{width:38px;height:38px;border-radius:12px;background:#c9f26b;color:#10251e!important;display:grid;place-items:center;font-weight:800;font-size:22px}
.brand-name{font:800 17px Manrope,sans-serif;letter-spacing:-.5px}.brand-sub{color:#a2b4aa!important;font-size:10px;letter-spacing:1.7px;text-transform:uppercase;margin-top:2px}
.side-cap{font-size:10px;letter-spacing:1.5px;color:#9caf9f!important;text-transform:uppercase;margin:22px 0 7px 10px}
.page-kicker{font:500 11px 'DM Mono',monospace;color:#6b8177;letter-spacing:1.2px;text-transform:uppercase}
h1,h2,h3{font-family:Manrope,sans-serif!important;letter-spacing:-.7px!important;color:#192a23}
h1{font-size:32px!important;margin:3px 0 7px!important} h2{font-size:23px!important} h3{font-size:17px!important}
.page-sub{color:#77847e;font-size:14px;margin:0 0 23px}
.hero{background:#10251e;border-radius:18px;padding:25px 28px;color:white;position:relative;overflow:hidden;margin:12px 0 20px}
.hero:after{content:'◈';position:absolute;right:42px;top:-35px;font-size:190px;color:#ffffff08;line-height:1}
.hero-label{font:500 10px 'DM Mono',monospace;letter-spacing:1.6px;color:#badbca;text-transform:uppercase}
.hero-title{font:700 25px Manrope,sans-serif;color:#fff;margin:9px 0 7px;letter-spacing:-.7px}.hero-copy{font-size:13px;color:#c1d0c8;max-width:660px}
.metric-card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:17px 18px;min-height:106px}
.metric-label{font-size:11px;color:#7b8982;text-transform:uppercase;letter-spacing:.8px}.metric-value{font:700 28px Manrope,sans-serif;color:#183528;margin:5px 0 2px}.metric-foot{font-size:11px;color:#87938d}
.panel{background:white;border:1px solid var(--line);border-radius:15px;padding:20px 22px;margin:12px 0}
.panel-title{font:700 15px Manrope,sans-serif;margin-bottom:4px}.panel-note{font-size:12px;color:#829088;margin-bottom:15px}
.pill{display:inline-block;padding:4px 9px;border-radius:20px;font:500 10px 'DM Mono',monospace;background:#edf3ee;color:#456355;margin:2px 4px 2px 0}
.badge{display:inline-block;border-radius:20px;padding:5px 10px;font:500 10px 'DM Mono',monospace}
.badge-high{background:#fbefed;color:#b64f49}.badge-medium{background:#fff5e5;color:#a8751f}.badge-low{background:#eaf5ee;color:#35724e}.badge-critical{background:#f8eaf0;color:#a43259}
.badge-current{background:#eaf5ee;color:#35724e}.badge-due{background:#fff5e5;color:#a8751f}.badge-outdated{background:#fbefed;color:#b64f49}
.threat-row{background:white;border:1px solid var(--line);border-radius:12px;padding:15px 17px;margin:8px 0}
.threat-title{font:600 14px Manrope,sans-serif}.mono{font:11px 'DM Mono',monospace;color:#839088}.small{font-size:12px;color:#77847e}
.flow{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.flow-node{background:#f0f5f1;border:1px solid #e1eae3;border-radius:9px;padding:10px 12px;font-size:12px;color:#395345}.flow-arrow{color:#96aa9d}
div[data-testid="stTabs"] button{font-size:13px}.stButton>button{border-radius:9px;font-weight:600;border:1px solid #dfe7e1}.stButton>button[kind="primary"]{background:#1c7355;border-color:#1c7355}
div[data-testid="stMetric"]{background:white;border:1px solid var(--line);padding:12px 14px;border-radius:12px}
.footnote{font-size:11px;color:#87938d;border-top:1px solid var(--line);padding-top:12px;margin-top:24px}
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def get_data():
    from autotara.config import get_config
    get_config(root_dir=PROJECT_DIR, reload=True)
    loader = DataLoader(root_dir=PROJECT_DIR)
    return loader, loader.load_all_knowledge_base()


loader, kb = get_data()
threats = kb["threat_patterns"]
controls = {x["id"]: x for x in kb["controls"]}
requirements = {x["id"]: x for x in kb["requirements"]}
tests = {x["id"]: x for x in kb["verification_tests"]}
mitigator = MitigationEngine(loader=loader)

if "decisions" not in st.session_state:
    st.session_state.decisions = {}
if "risk_overrides" not in st.session_state:
    st.session_state.risk_overrides = {}

with st.sidebar:
    st.markdown('<div class="brand"><div class="brand-icon">◈</div><div><div class="brand-name">AutoTARA AI</div><div class="brand-sub">Security workspace</div></div></div>', unsafe_allow_html=True)
    st.markdown('<div class="side-cap">Workspace</div>', unsafe_allow_html=True)
    page = st.radio("Navigate", ["Overview", "Threat analysis", "Architecture", "Traceability", "Knowledge base"], label_visibility="collapsed")
    st.markdown('<div class="side-cap">Active project</div>', unsafe_allow_html=True)
    st.markdown("**Connected Vehicle Platform**  \n<span style='font-size:11px;color:#9caf9f'>TELEMATICS · OTA · REMOTE CONTROL</span>", unsafe_allow_html=True)
    version = st.selectbox("Architecture baseline", ["v1 · Core platform", "v2 · Bluetooth adapter"], label_visibility="visible")
    baseline = "v2" if version.startswith("v2") else "v1"
    st.markdown('<div class="side-cap">Review status</div>', unsafe_allow_html=True)
    reviewed = sum(v in ("Accepted", "Rejected") for v in st.session_state.decisions.values())
    st.markdown(f"<span class='badge badge-current'>{reviewed} reviewed</span> <span class='badge badge-due'>{len(threats)-reviewed} need review</span>", unsafe_allow_html=True)
    st.markdown('<div style="height:26vh"></div><div style="border-top:1px solid #ffffff20;padding-top:14px;color:#9caf9f;font-size:11px">Prototype workspace · Human review required</div>', unsafe_allow_html=True)

architecture = loader.load_architecture(baseline)
analyzer = ArchitectureAnalyzer(architecture)
surfaces = {aid: analyzer.derive_attack_surface(aid) for aid in analyzer.assets}
patterns_by_id = {x["id"]: x for x in threats}


def heading(kicker, title, sub):
    st.markdown(f'<div class="page-kicker">{kicker}</div><h1>{title}</h1><div class="page-sub">{sub}</div>', unsafe_allow_html=True)


def metric(label, value, foot):
    st.markdown(f'<div class="metric-card"><div class="metric-label">{label}</div><div class="metric-value">{value}</div><div class="metric-foot">{foot}</div></div>', unsafe_allow_html=True)


def risk_for(pid):
    return st.session_state.risk_overrides.get(pid, {"impact": 3, "feasibility": 3})


def risk_chip(band):
    return f"<span class='badge badge-{band.lower()}'>{band.upper()}</span>"


def freshness_chip(status):
    cls = {"Current": "badge-current", "Review Due": "badge-due", "Outdated": "badge-outdated"}.get(status, "badge-due")
    return f"<span class='badge {cls}'>{status.upper()}</span>"


def threat_asset(pattern):
    candidates = []
    for aid, surface in surfaces.items():
        if pattern.get("trust_boundary") in surface.trust_boundary_ids:
            candidates.append((aid, analyzer.assets[aid]))
    if candidates:
        return candidates[0]
    return next(iter(analyzer.assets.items()))


def display_threat_detail(pattern):
    pid = pattern["id"]
    aid, asset = threat_asset(pattern)
    surface = surfaces[aid]
    st.markdown(f"### {pattern['title']}  <span class='mono'>{pid}</span>", unsafe_allow_html=True)
    st.markdown(f"{risk_chip(RiskEngine.calculate_risk(**{'impact': risk_for(pid)['impact'], 'attack_feasibility': risk_for(pid)['feasibility']}).band)} &nbsp; {freshness_chip(pattern['freshness_status'])}", unsafe_allow_html=True)
    left, right = st.columns([1.25, .9], gap="large")
    with left:
        st.markdown("<div class='panel'><div class='panel-title'>Threat scenario</div></div>", unsafe_allow_html=True)
        st.write(pattern.get("threat_scenario", pattern.get("description", "Controlled knowledge-base pattern matched to this architecture context.")))
        st.markdown("<div class='panel'><div class='panel-title'>Potential damage</div></div>", unsafe_allow_html=True)
        st.write(pattern.get("damage_scenario", "Validate potential impacts with a qualified reviewer."))
        st.markdown('<div class="panel"><div class="panel-title">Why this threat?</div><div class="panel-note">Architecture context and controlled knowledge evidence</div></div>', unsafe_allow_html=True)
        st.write(f"**Affected asset** · {asset['name']} ({aid})")
        st.write(f"**Trust boundary** · {pattern.get('trust_boundary', '—')}")
        st.write(f"**Connected interfaces** · {', '.join(surface.interface_ids) or 'No connected interfaces'}")
        st.write(f"**Protocols** · {', '.join(surface.protocols) or 'Not specified'}")
        st.write(f"**Matching knowledge pattern** · {pattern.get('title', pid)} · v{pattern.get('version', '1.0')}")
        st.write("**Assumption** · The asset and boundary are in scope; threat applicability requires engineer confirmation.")
        st.caption(pattern.get("source_note", "Controlled threat knowledge base. Validate assumptions with a qualified reviewer."))
    with right:
        st.markdown('<div class="panel"><div class="panel-title">Prototype risk assessment</div><div class="panel-note">Transparent score = Impact × Attack feasibility</div></div>', unsafe_allow_html=True)
        score_cols = st.columns(2)
        with score_cols[0]: impact = st.select_slider("Impact", options=[1,2,3,4,5], value=risk_for(pid)["impact"], key=f"impact_{pid}")
        with score_cols[1]: feas = st.select_slider("Feasibility", options=[1,2,3,4,5], value=risk_for(pid)["feasibility"], key=f"feas_{pid}")
        assessment = RiskEngine.calculate_risk(impact, feas)
        st.session_state.risk_overrides[pid] = {"impact": impact, "feasibility": feas}
        st.metric("Risk score", f"{assessment.score} / 25", assessment.band)
        bundle = mitigator.draft_mitigation_bundle(pid, asset["name"])
        t1, t2, t3 = st.tabs(["Controls", "Requirements", "Verification"])
        with t1:
            for control in bundle.controls[:5]:
                st.markdown(f"**{control['id']} · {control['name']}**  \n<span class='small'>{control['description']}</span>", unsafe_allow_html=True)
                st.markdown("")
        with t2:
            for req in bundle.requirements[:5]:
                st.markdown(f"**{req.id} · {req.title}**  \n<span class='small'>{req.requirement_text}</span>", unsafe_allow_html=True)
        with t3:
            shown = 0
            for req in bundle.requirements:
                for test in req.tests:
                    st.markdown(f"**{test['id']} · {test['title']}**  \n<span class='small'>{test['objective']}</span>", unsafe_allow_html=True)
                    shown += 1
                    if shown >= 5: break
                if shown >= 5: break
            if not shown: st.caption("No linked verification test found.")
    st.markdown("#### Reviewer decision")
    c1,c2,c3=st.columns([1.3,1.3,2.4])
    current=st.session_state.decisions.get(pid,"Needs review")
    with c1:
        if st.button("Accept recommendation", key=f"accept_{pid}", type="primary", use_container_width=True): st.session_state.decisions[pid]="Accepted"; st.rerun()
    with c2:
        if st.button("Reject recommendation", key=f"reject_{pid}", use_container_width=True): st.session_state.decisions[pid]="Rejected"; st.rerun()
    with c3: st.caption(f"Current decision: **{current}** · Human approval owns all risk acceptance.")


if page == "Overview":
    heading("PROJECT WORKSPACE / CONNECTED VEHICLE", "Security posture at a glance", "A change aware TARA workspace for architecture, threats, risk, and evidence.")
    st.markdown('<div class="hero"><div class="hero-label">Active assessment · Connected Vehicle Platform</div><div class="hero-title">Make every security decision traceable.</div><div class="hero-copy">Review architecture driven threat recommendations, understand why they apply, and connect each finding to controls, requirements, and verification tests.</div></div>', unsafe_allow_html=True)
    fresh={k:sum(x["freshness_status"]==k for x in threats) for k in ["Current","Review Due","Outdated"]}
    critical=sum(RiskEngine.calculate_risk(**{"impact":risk_for(t["id"])["impact"],"attack_feasibility":risk_for(t["id"])["feasibility"]}).band in ("High","Critical") for t in threats)
    cols=st.columns(4)
    with cols[0]:metric("Assets in scope",len(analyzer.assets),"Across the active baseline")
    with cols[1]:metric("Threat patterns",len(threats),"Controlled knowledge base")
    with cols[2]:metric("Require attention",fresh["Outdated"]+fresh["Review Due"],f"{fresh['Outdated']} outdated · {fresh['Review Due']} due")
    with cols[3]:metric("High risk findings",critical,"Illustrative 1–25 score")
    st.markdown('<div class="panel"><div class="panel-title">Assessment flow</div><div class="panel-note">From architecture context to human review</div><div class="flow"><span class="flow-node">01 · Architecture</span><span class="flow-arrow">→</span><span class="flow-node">02 · Attack surface</span><span class="flow-arrow">→</span><span class="flow-node">03 · Threat patterns</span><span class="flow-arrow">→</span><span class="flow-node">04 · Risk & controls</span><span class="flow-arrow">→</span><span class="flow-node">05 · Reviewer decision</span></div></div>', unsafe_allow_html=True)
    a,b=st.columns([1.2,.8],gap="large")
    with a:
        st.markdown('<div class="panel-title">Priority review queue</div><div class="panel-note">Knowledge freshness and high impact patterns to review first</div>',unsafe_allow_html=True)
        order={"Outdated":0,"Review Due":1,"Current":2}
        for p in sorted(threats,key=lambda x:(order[x["freshness_status"]],x["id"]))[:5]:
            st.markdown(f"<div class='threat-row'><span class='mono'>{p['id']}</span> &nbsp; <span class='threat-title'>{p['title']}</span><br><span class='small'>Boundary {p.get('trust_boundary','—')} · {freshness_chip(p['freshness_status'])} {risk_chip(RiskEngine.calculate_risk(**{'impact':risk_for(p['id'])['impact'],'attack_feasibility':risk_for(p['id'])['feasibility']}).band)}</span></div>",unsafe_allow_html=True)
    with b:
        st.markdown('<div class="panel-title">Knowledge health</div><div class="panel-note">Threat pattern review status · reference date 13 Oct 2026</div>',unsafe_allow_html=True)
        for name,count,color in [("Current",fresh["Current"],"#40805b"),("Review due",fresh["Review Due"],"#c48a2a"),("Outdated",fresh["Outdated"],"#c9564f")]:
            st.markdown(f"**{name}** <span style='float:right'>{count}</span>",unsafe_allow_html=True); st.progress(count/max(1,len(threats)),text=f"{count} patterns")
        st.caption("Freshness is deterministic from each pattern’s next review date.")
    st.markdown("### System context")
    st.markdown('<div class="panel"><div class="flow"><span class="flow-node">Mobile App</span><span class="flow-arrow">→</span><span class="flow-node">Cloud & OTA</span><span class="flow-arrow">→</span><span class="flow-node">TCU</span><span class="flow-arrow">→</span><span class="flow-node">Gateway</span><span class="flow-arrow">→</span><span class="flow-node">Vehicle ECUs</span></div></div>',unsafe_allow_html=True)
    st.markdown('<div class="footnote">Prototype risk scoring is educational guidance only. Qualified cybersecurity reviewers retain final decisions. No production vehicle connection or active exploitation.</div>',unsafe_allow_html=True)

elif page == "Threat analysis":
    heading("ANALYSIS / RECOMMENDATIONS", "Threat analysis", "Review controlled patterns against architecture context, score risk, and inspect linked evidence.")
    filters=st.columns([1.3,1,1,1])
    with filters[0]: query=st.text_input("Search patterns",placeholder="Threat, asset, or ID")
    with filters[1]: boundary=st.selectbox("Trust boundary",["All boundaries"]+sorted(analyzer.trust_boundaries))
    with filters[2]: fresh_filter=st.selectbox("Freshness",["All statuses","Current","Review Due","Outdated"])
    with filters[3]: risk_filter=st.selectbox("Risk band",["All bands","Low","Medium","High","Critical"])
    visible=[]
    for p in threats:
        text=(p["id"]+" "+p.get("title","")+" "+p.get("description","")).lower()
        risk=RiskEngine.calculate_risk(**{"impact":risk_for(p["id"])["impact"],"attack_feasibility":risk_for(p["id"])["feasibility"]}).band
        if query.lower() not in text:continue
        if boundary!="All boundaries" and p.get("trust_boundary")!=boundary:continue
        if fresh_filter!="All statuses" and p["freshness_status"]!=fresh_filter:continue
        if risk_filter!="All bands" and risk!=risk_filter:continue
        visible.append(p)
    st.caption(f"{len(visible)} patterns · Select a finding to inspect its explanation, risk, and traceability.")
    rows=st.columns([1,1],gap="large")
    for i,p in enumerate(visible):
        with rows[i%2]:
            risk=RiskEngine.calculate_risk(**{"impact":risk_for(p["id"])["impact"],"attack_feasibility":risk_for(p["id"])["feasibility"]})
            aid,asset=threat_asset(p)
            st.markdown(f"<div class='threat-row'><span class='mono'>{p['id']} · {p.get('trust_boundary','—')}</span><br><span class='threat-title'>{p['title']}</span><br><span class='small'>{asset['name']} · score {risk.score}/25</span><br>{risk_chip(risk.band)} {freshness_chip(p['freshness_status'])}</div>",unsafe_allow_html=True)
            if st.button("Inspect finding →",key=f"inspect_{p['id']}",use_container_width=True): st.session_state.selected_threat=p["id"]
    selected=st.session_state.get("selected_threat")
    if selected and selected in patterns_by_id:
        st.divider(); display_threat_detail(patterns_by_id[selected])
    elif visible:
        st.divider(); display_threat_detail(visible[0])

elif page == "Architecture":
    heading("SYSTEM MODEL / CHANGE IMPACT", "Architecture & change impact", "Understand the active baseline and review artifacts affected by a platform change.")
    v1=loader.load_architecture("v1"); v2=loader.load_architecture("v2")
    old_c={x["id"]:x for x in v1["components"]}; new_c={x["id"]:x for x in v2["components"]}
    old_i={x["id"]:x for x in v1["interfaces"]}; new_i={x["id"]:x for x in v2["interfaces"]}
    cc=st.columns(4)
    with cc[0]:metric("Components",len(analyzer.components),"In selected baseline")
    with cc[1]:metric("Interfaces",len(analyzer.interfaces),"Connected paths")
    with cc[2]:metric("Trust boundaries",len(analyzer.trust_boundaries),"Security transitions")
    with cc[3]:metric("Data flows",len(analyzer.data_flows),"Modeled exchanges")
    st.markdown("### Vehicle system topology")
    st.markdown('<div class="panel"><div class="flow"><span class="flow-node">Mobile App<br><small>Untrusted</small></span><span class="flow-arrow">TB-01 →</span><span class="flow-node">Cloud Backend<br><small>Trusted</small></span><span class="flow-arrow">TB-02 →</span><span class="flow-node">TCU<br><small>Semi-trusted</small></span><span class="flow-arrow">TB-03 →</span><span class="flow-node">Gateway ECU<br><small>Trusted</small></span><span class="flow-arrow">CAN / Ethernet →</span><span class="flow-node">Vehicle ECUs</span></div></div>',unsafe_allow_html=True)
    tab1,tab2,tab3=st.tabs(["Assets & surfaces","Interfaces","Baseline diff"])
    with tab1:
        asset_rows=[]
        for aid,asset in analyzer.assets.items():
            surf=surfaces[aid]
            asset_rows.append({"ID":aid,"Asset":asset["name"],"Type":asset["type"],"Interfaces":", ".join(surf.interface_ids),"Boundaries":", ".join(surf.trust_boundary_ids)})
        st.dataframe(pd.DataFrame(asset_rows),use_container_width=True,hide_index=True)
    with tab2:
        st.dataframe(pd.DataFrame([{"ID":i["id"],"Interface":i["name"],"Source":i["source_component_id"],"Target":i["target_component_id"],"Protocol":i["protocol"],"Boundary":i["trust_boundary_id"]} for i in analyzer.interfaces.values()]),use_container_width=True,hide_index=True)
    with tab3:
        added=set(new_c)-set(old_c); added_if=set(new_i)-set(old_i)
        st.markdown("**v1 → v2 change set**")
        for cid in added:
            c=new_c[cid]; st.markdown(f"<div class='threat-row'><span class='badge badge-due'>COMPONENT ADDED</span> &nbsp; <b>{cid} · {c['name']}</b><br><span class='small'>{c['description']}</span></div>",unsafe_allow_html=True)
        for iid in added_if:
            i=new_i[iid]; st.markdown(f"<div class='threat-row'><span class='badge badge-due'>INTERFACE ADDED</span> &nbsp; <b>{iid} · {i['name']}</b><br><span class='small'>{i['protocol']} · trust boundary {i['trust_boundary_id']}</span></div>",unsafe_allow_html=True)
        affected=[p for p in threats if p.get("trust_boundary")=="TB-05"]
        st.markdown(f"**Reassessment queue · {len(affected)} threat patterns activated**")
        for p in affected: st.markdown(f"{p['id']} · {p['title']} — {freshness_chip(p['freshness_status'])}",unsafe_allow_html=True)
        st.info("Adding the Bluetooth diagnostic adapter introduces TB-05 and activates pairing and adapter exploitation patterns for expert review.")

elif page == "Traceability":
    heading("EVIDENCE / TRACEABILITY", "Traceability chain", "Follow the evidence from architecture assets through threats, controls, requirements, tests, and reviewer decisions.")
    derived=loader.build_derived_traceability(kb["threat_patterns"],kb["controls"],kb["requirements"],kb["verification_tests"])
    total=len(threats); complete=0; rows=[]
    for p in threats:
        cs=p.get("suggested_control_ids",[]); rs=set(); ts=set()
        for cid in cs:
            rs.update(derived["control_to_requirements"].get(cid,[]))
        for rid in rs:ts.update(derived["requirement_to_tests"].get(rid,[]))
        ok=bool(cs and rs and ts)
        complete+=ok
        aid,asset=threat_asset(p)
        rows.append({"Asset":asset["name"],"Threat":p["id"],"Pattern":p["title"],"Controls":len(cs),"Requirements":len(rs),"Tests":len(ts),"Decision":st.session_state.decisions.get(p["id"],"Needs review"),"Complete":"Yes" if ok else "Incomplete"})
    c=st.columns(4)
    with c[0]:metric("Threats mapped",total,"Controlled pattern set")
    with c[1]:metric("Traceability complete",f"{complete/total*100:.0f}%",f"{complete} of {total} have control → requirement → test")
    with c[2]:metric("Reviewer decisions",reviewed,f"{total-reviewed} pending")
    with c[3]:metric("Evidence records",len(kb["controls"])+len(kb["requirements"])+len(kb["verification_tests"]),"Controls + requirements + tests")
    st.markdown('<div class="panel"><div class="flow"><span class="flow-node">Asset</span><span class="flow-arrow">→</span><span class="flow-node">Interface</span><span class="flow-arrow">→</span><span class="flow-node">Threat</span><span class="flow-arrow">→</span><span class="flow-node">Risk</span><span class="flow-arrow">→</span><span class="flow-node">Control</span><span class="flow-arrow">→</span><span class="flow-node">Requirement</span><span class="flow-arrow">→</span><span class="flow-node">Test</span><span class="flow-arrow">→</span><span class="flow-node">Review</span></div></div>',unsafe_allow_html=True)
    st.dataframe(pd.DataFrame(rows),use_container_width=True,hide_index=True)
    export={"project":"Connected Vehicle Platform","baseline":baseline,"reference_date":"2026-10-13","traceability":rows}
    e1,e2=st.columns(2)
    with e1:st.download_button("Download traceability CSV",pd.DataFrame(rows).to_csv(index=False),"autotara_traceability.csv","text/csv",use_container_width=True)
    with e2:st.download_button("Download assessment JSON",json.dumps(export,indent=2),"autotara_assessment.json","application/json",use_container_width=True)

else:
    heading("GOVERNED KNOWLEDGE / FRESHNESS", "Threat knowledge base", "Owned, versioned security patterns with deterministic freshness indicators.")
    counts={s:sum(x["freshness_status"]==s for x in threats) for s in ["Current","Review Due","Outdated"]}
    m=st.columns(3)
    for col,status in zip(m,["Current","Review Due","Outdated"]):
        with col:metric(status,counts[status],"Next review date rule")
    search=st.text_input("Find a threat pattern",placeholder="ID, title, trust boundary, or owner")
    due_only=st.toggle("Show patterns needing review",value=False)
    data=[]
    for p in threats:
        hay=" ".join([p.get("id",""),p.get("title",""),p.get("trust_boundary",""),p.get("owner","")]).lower()
        if search.lower() not in hay:continue
        if due_only and p["freshness_status"]=="Current":continue
        data.append({"ID":p["id"],"Pattern":p["title"],"Boundary":p["trust_boundary"],"Owner":p.get("owner","—"),"Version":p.get("version","—"),"Last reviewed":p.get("last_review_date","—"),"Next review":p.get("next_review_date","—"),"Status":p["freshness_status"]})
    st.dataframe(pd.DataFrame(data),use_container_width=True,hide_index=True)
    st.markdown("### Freshness rule")
    st.markdown('<div class="panel"><span class="badge badge-current">CURRENT</span> next review is more than 30 days ahead &nbsp;&nbsp; <span class="badge badge-due">REVIEW DUE</span> due within 30 days or overdue up to 180 days &nbsp;&nbsp; <span class="badge badge-outdated">OUTDATED</span> overdue by more than 180 days</div>',unsafe_allow_html=True)
    st.caption("Statuses use the controlled reference date 13 October 2026 so reports are reproducible.")

