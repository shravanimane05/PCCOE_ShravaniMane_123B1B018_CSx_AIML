"""NexTARA — alternate visual concept for the AutoTARA case study."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from autotara.architecture_analyzer import ArchitectureAnalyzer
from autotara.config import get_config
from autotara.data_loader import DataLoader
from autotara.mitigation_engine import MitigationEngine
from autotara.risk_engine import RiskEngine

get_config(root_dir=ROOT, reload=True)
st.set_page_config(page_title="NexTARA | Vehicle Security", page_icon="N", layout="wide", initial_sidebar_state="collapsed")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Manrope:wght@400;500;600;700;800&family=Source+Sans+3:wght@400;500;600;700&display=swap');
:root{--navy:#111827;--deep:#0b1220;--surface:#fff;--canvas:#f3f5f8;--muted:#788395;--line:#e2e7ee;--orange:#f07842;--mint:#21a67a;--blue:#3d70d6}
html,body,[class*="css"]{font-family:'Source Sans 3',sans-serif;color:#202b3b} .stApp{background:var(--canvas)}
.block-container{max-width:1450px;padding:1.1rem 2.2rem 3rem!important}
.topbar{margin:0 0 18px;padding:15px 20px;background:var(--deep);display:flex;align-items:center;justify-content:space-between;color:#f3f5f7;border:1px solid #263246;border-radius:10px;min-height:68px}
.logo{font:800 19px Manrope,sans-serif;letter-spacing:-.7px}.logo span{color:var(--orange)}.logo-sub{font:500 9px 'IBM Plex Mono',monospace;letter-spacing:1.5px;color:#8d9aab;text-transform:uppercase;margin-top:2px}
.topmeta{font:11px 'IBM Plex Mono',monospace;color:#aab5c5}.live{display:inline-block;width:7px;height:7px;background:#42d49f;border-radius:50%;margin-right:7px;box-shadow:0 0 10px #42d49f}
h1,h2,h3{font-family:Manrope,sans-serif!important;letter-spacing:-.7px!important;color:#172235}h1{font-size:30px!important;margin:4px 0!important}h2{font-size:22px!important}h3{font-size:17px!important}
.eyebrow{font:600 10px 'IBM Plex Mono',monospace;text-transform:uppercase;letter-spacing:1.5px;color:#758196}.sub{color:#748094;font-size:14px;margin-bottom:19px}
.section{background:white;border:1px solid var(--line);border-radius:11px;padding:19px 20px;margin:12px 0;box-shadow:0 2px 8px #1c2d4210}.section-title{font:700 14px Manrope,sans-serif;color:#233149}.section-sub{font-size:12px;color:#8791a0;margin:3px 0 13px}
.stat{background:white;border:1px solid var(--line);border-radius:11px;padding:15px 17px;min-height:97px;box-shadow:0 2px 8px #1c2d4209}.stat-label{font:600 10px 'IBM Plex Mono',monospace;color:#7d8999;text-transform:uppercase;letter-spacing:.7px}.stat-value{font:800 27px Manrope,sans-serif;color:#1c293e;margin:4px 0 0}.stat-foot{font-size:11px;color:#909aaa}
.flag{display:inline-block;font:600 9px 'IBM Plex Mono',monospace;letter-spacing:.4px;padding:4px 7px;border-radius:4px;text-transform:uppercase;background:#eef2f6;color:#5b687b}.f-critical{background:#fde8e4;color:#bd4b37}.f-high{background:#fff0e4;color:#c46a26}.f-medium{background:#fff5d9;color:#9d791d}.f-low{background:#e5f5ed;color:#2c8054}.f-current{background:#e4f4ec;color:#2d7c52}.f-due{background:#fff4d9;color:#9d791d}.f-outdated{background:#fde8e4;color:#bd4b37}
.finding{background:white;border:1px solid var(--line);border-radius:9px;padding:13px 15px;margin:8px 0}.finding:hover{border-color:#aebbd0}.finding-id{font:11px 'IBM Plex Mono',monospace;color:#8894a4}.finding-title{font:700 13px Manrope,sans-serif;color:#243149;margin:3px 0}.finding-meta{font-size:11px;color:#8791a0}
.timeline{display:flex;align-items:center;gap:0;overflow-x:auto}.node{border:1px solid #dce2ea;background:#f8fafc;border-radius:7px;padding:9px 11px;font-size:11px;font-weight:600;white-space:nowrap;color:#37445b}.connector{font:14px 'IBM Plex Mono',monospace;color:#9aa5b4;padding:0 7px}
div[data-testid="stTabs"] button{font-size:13px;font-weight:600}.stButton>button{border-radius:7px;font-weight:700;border-color:#d9e0e8}.stButton>button[kind="primary"]{background:#1b263a;border-color:#1b263a}.stDownloadButton button{border-radius:7px}
.note{font-size:11px;color:#8b95a2;border-top:1px solid var(--line);padding-top:12px;margin-top:20px}
section[data-testid="stSidebar"]{display:none}
div[data-testid="stRadio"]>label{display:none}
div[data-testid="stRadio"] div[role="radiogroup"]{display:flex;gap:7px;background:#e9edf3;border:1px solid #dce2eb;padding:5px;border-radius:10px;width:fit-content;margin:0 0 17px}
div[data-testid="stRadio"] div[role="radiogroup"] label{background:transparent;border-radius:7px;padding:8px 15px;margin:0;color:#667387;font-size:13px;font-weight:700;transition:all .15s}
div[data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked){background:#182337;color:white;box-shadow:0 2px 5px #18233730}
div[data-testid="stRadio"] div[role="radiogroup"] label>div:first-child{display:none}
.hero{background:linear-gradient(112deg,#111b2c 0%,#1a2a43 62%,#29415b 100%);border:1px solid #293b53;border-radius:14px;padding:30px 32px;margin:16px 0 20px;color:white;position:relative;overflow:hidden;min-height:210px}
.hero:after{content:'N';position:absolute;right:55px;top:-60px;font:800 260px Manrope,sans-serif;color:#ffffff08;line-height:1}
.hero-kicker{font:600 10px 'IBM Plex Mono',monospace;letter-spacing:1.6px;color:#ffb58e;text-transform:uppercase}.hero-title{font:800 29px Manrope,sans-serif;color:#fff;margin:12px 0 7px;letter-spacing:-1px;position:relative;z-index:1}.hero-copy{font-size:14px;color:#bdc8d6;max-width:690px;position:relative;z-index:1}.hero-chip{display:inline-block;margin-top:15px;border:1px solid #ffffff24;border-radius:5px;padding:6px 9px;color:#d9e3ed;font:10px 'IBM Plex Mono',monospace}
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def resources():
    dl=DataLoader(root_dir=ROOT)
    return dl,dl.load_all_knowledge_base()

loader,kb=resources(); patterns=kb["threat_patterns"]; byid={p["id"]:p for p in patterns}
mitigator=MitigationEngine(loader)
if "nex_decisions" not in st.session_state:st.session_state.nex_decisions={}
if "nex_risks" not in st.session_state:st.session_state.nex_risks={}

st.markdown("<div class='topbar'><div><div class='logo'>NEX<span>TARA</span></div><div class='logo-sub'>Vehicle security intelligence</div></div><div class='topmeta'><span class='live'></span>ASSESSMENT ACTIVE &nbsp; / &nbsp; CONNECTED VEHICLE PLATFORM</div></div>",unsafe_allow_html=True)
if "nex_page" not in st.session_state:st.session_state.nex_page="Command center"
page=st.radio("Workspace",["Command center","Threat register","System model","Evidence & governance"],horizontal=True,label_visibility="collapsed",key="nex_page")
with st.container():
    c1,c2=st.columns([3,1.1])
    with c1:
        st.markdown("<div class='eyebrow'>PROGRAM / CONNECTED VEHICLE · TARA-042</div>",unsafe_allow_html=True)
    with c2:
        baseline_label=st.selectbox("Architecture revision",["Revision 01 · Core","Revision 02 · Wireless diagnostic"],label_visibility="collapsed")
baseline="v2" if baseline_label.startswith("Revision 02") else "v1"
architecture=loader.load_architecture(baseline); analyzer=ArchitectureAnalyzer(architecture)
surfaces={aid:analyzer.derive_attack_surface(aid) for aid in analyzer.assets}

def head(kicker,title,sub):st.markdown(f"<div class='eyebrow'>{kicker}</div><h1>{title}</h1><div class='sub'>{sub}</div>",unsafe_allow_html=True)
def stat(label,value,foot):st.markdown(f"<div class='stat'><div class='stat-label'>{label}</div><div class='stat-value'>{value}</div><div class='stat-foot'>{foot}</div></div>",unsafe_allow_html=True)
def badge(text,kind):return f"<span class='flag f-{kind}'>{text}</span>"
def risk(pid):return st.session_state.nex_risks.get(pid,{"impact":3,"feasibility":3})
def band(pid):return RiskEngine.calculate_risk(risk(pid)["impact"],risk(pid)["feasibility"]).band
def freshness(p):return {"Current":"current","Review Due":"due","Outdated":"outdated"}[p["freshness_status"]]
def target_asset(p):
    for aid,a in analyzer.assets.items():
        if p.get("trust_boundary") in surfaces[aid].trust_boundary_ids:return aid,a
    aid=next(iter(analyzer.assets));return aid,analyzer.assets[aid]

if page=="Command center":
    st.markdown("<div class='hero'><div class='hero-kicker'>Connected vehicle platform &nbsp; / &nbsp; security assessment</div><div class='hero-title'>See the exposure.<br>Strengthen the system.</div><div class='hero-copy'>Bring architecture, threat scenarios and engineering evidence into one review workspace. Start with the findings that need attention and follow every recommendation to its control and test.</div><span class='hero-chip'>BASELINE " + ("02 · BLUETOOTH DIAGNOSTIC" if baseline=="v2" else "01 · CORE PLATFORM") + "</span><span class='hero-chip' style='margin-left:7px'>30 CONTROLLED THREAT PATTERNS</span></div>",unsafe_allow_html=True)
    counts={s:sum(p["freshness_status"]==s for p in patterns) for s in ["Current","Review Due","Outdated"]}
    high=sum(band(p["id"]) in ("High","Critical") for p in patterns)
    accepted=sum(v in ("Accepted","Rejected") for v in st.session_state.nex_decisions.values())
    m=st.columns(4)
    with m[0]:stat("In-scope assets",len(analyzer.assets),f"{len(analyzer.components)} system components")
    with m[1]:stat("Threat scenarios",len(patterns),"Versioned pattern library")
    with m[2]:stat("Priority findings",high,"High + critical prototype score")
    with m[3]:stat("Evidence reviewed",f"{accepted}/{len(patterns)}","Engineer disposition")
    l,r=st.columns([1.45,.8],gap="large")
    with l:
        st.markdown("<div class='section-title'>Assessment pathway</div><div class='section-sub'>From system boundary to an accountable review decision</div><div class='timeline'><span class='node'>01 &nbsp; System</span><span class='connector'>/</span><span class='node'>02 &nbsp; Exposure</span><span class='connector'>/</span><span class='node'>03 &nbsp; Scenarios</span><span class='connector'>/</span><span class='node'>04 &nbsp; Safeguards</span><span class='connector'>/</span><span class='node'>05 &nbsp; Sign-off</span></div>",unsafe_allow_html=True)
        st.markdown("<div style='height:12px'></div><div class='section-title'>Review focus</div><div class='section-sub'>Knowledge requiring attention, ordered by status</div>",unsafe_allow_html=True)
        order={"Outdated":0,"Review Due":1,"Current":2}
        for p in sorted(patterns,key=lambda x:(order[x["freshness_status"]],x["id"]))[:6]:
            aid,a=target_asset(p)
            st.markdown(f"<div class='finding'><span class='finding-id'>{p['id']} &nbsp; / &nbsp; {p.get('trust_boundary','—')}</span> &nbsp; {badge(band(p['id']),band(p['id']).lower())}<div class='finding-title'>{p['title']}</div><div class='finding-meta'>{a['name']} &nbsp; · &nbsp; {badge(p['freshness_status'],freshness(p))}</div></div>",unsafe_allow_html=True)
    with r:
        st.markdown("<div class='section-title'>Knowledge lifecycle</div><div class='section-sub'>Pattern freshness · anchored to 13 Oct 2026</div>",unsafe_allow_html=True)
        for s,label in [("Current","CURRENT"),("Review Due","DUE FOR REVIEW"),("Outdated","OUTDATED")]:
            st.markdown(f"<div style='margin:14px 0 4px'>{badge(label,freshness({'freshness_status':s}))}<span style='float:right;font-weight:700'>{counts[s]}</span></div>",unsafe_allow_html=True)
            st.progress(counts[s]/len(patterns))
        st.markdown("<div class='section'><div class='section-title'>Architecture snapshot</div><div class='section-sub'>Active revision</div><b>Connected Vehicle Telematics</b><p style='font-size:12px;color:#788395'>Mobile application, cloud command services, OTA delivery, TCU, gateway, vehicle ECUs.</p></div>",unsafe_allow_html=True)
        st.markdown("<div class='note'>Risk uses an illustrative Impact × Feasibility scale. No decision is final without an authorized cybersecurity reviewer.</div>",unsafe_allow_html=True)
    start_col, spacer, arch_col=st.columns([1.15,3,1.15])
    with start_col:
        st.button("Open threat review →",type="primary",use_container_width=True,on_click=lambda:st.session_state.update(nex_page="Threat register"))
    with arch_col:
        st.button("Inspect architecture",use_container_width=True,on_click=lambda:st.session_state.update(nex_page="System model"))
    st.markdown("<div class='section'><div class='section-title'>Trust-zone journey</div><div class='section-sub'>Core remote-control and in-vehicle route</div><div class='timeline'><span class='node'>MOBILE APP</span><span class='connector'>TB-01 →</span><span class='node'>CLOUD / OTA</span><span class='connector'>TB-02 →</span><span class='node'>TELEMATICS UNIT</span><span class='connector'>TB-03 →</span><span class='node'>CENTRAL GATEWAY</span><span class='connector'>→</span><span class='node'>VEHICLE NETWORK</span></div></div>",unsafe_allow_html=True)

elif page=="Threat register":
    head("FINDINGS / REVIEW QUEUE","Threat register","Filter the controlled library, inspect attack context, assign prototype risk, and record a reviewer disposition.")
    f=st.columns([1.4,1,1,1])
    with f[0]:q=st.text_input("Search",placeholder="Search scenarios, IDs, assets…")
    with f[1]:tb=st.selectbox("Boundary",["Any boundary"]+sorted(analyzer.trust_boundaries))
    with f[2]:fs=st.selectbox("Knowledge status",["Any status","Current","Review Due","Outdated"])
    with f[3]:rb=st.selectbox("Prototype band",["Any band","Low","Medium","High","Critical"])
    matches=[]
    for p in patterns:
        hay=(p["id"]+p.get("title","")+p.get("description","")+p.get("threat_scenario","")).lower()
        if q.lower() not in hay or tb!="Any boundary" and p.get("trust_boundary")!=tb or fs!="Any status" and p["freshness_status"]!=fs or rb!="Any band" and band(p["id"])!=rb:continue
        matches.append(p)
    st.caption(f"{len(matches)} matching scenarios · Recommendations are prompts for engineering review.")
    left,right=st.columns([.85,1.45],gap="large")
    with left:
        for p in matches:
            aid,a=target_asset(p)
            st.markdown(f"<div class='finding'><span class='finding-id'>{p['id']} · {p.get('trust_boundary','—')}</span> &nbsp; {badge(band(p['id']),band(p['id']).lower())}<div class='finding-title'>{p['title']}</div><div class='finding-meta'>{a['name']} &nbsp; · &nbsp; {badge(p['freshness_status'],freshness(p))}</div></div>",unsafe_allow_html=True)
            if st.button("Open review",key=f"open_{p['id']}",use_container_width=True):st.session_state.nex_selected=p["id"]
    selected=st.session_state.get("nex_selected")
    active=byid.get(selected) if selected in byid else (matches[0] if matches else None)
    with right:
        if active:
            p=active;pid=p["id"];aid,a=target_asset(p);surface=surfaces[aid]
            st.markdown(f"<div class='section'><div class='eyebrow'>{pid} / {p.get('trust_boundary','—')} / REVIEW DETAIL</div><h2>{p['title']}</h2>{badge(band(pid),band(pid).lower())} &nbsp; {badge(p['freshness_status'],freshness(p))}</div>",unsafe_allow_html=True)
            tscenario=p.get("threat_scenario",p.get("description","Scenario details unavailable."))
            st.markdown("**Threat scenario**");st.write(tscenario)
            st.markdown("**Potential damage**");st.write(p.get("damage_scenario","Confirm potential impacts during review."))
            with st.expander("Why is this pattern relevant?",expanded=True):
                st.write(f"**Asset:** {a['name']} ({aid})")
                st.write(f"**Boundary:** {p.get('trust_boundary','—')} · **Interfaces:** {', '.join(surface.interface_ids) or 'None'}")
                st.write(f"**Protocols:** {', '.join(surface.protocols) or 'Not specified'}")
                st.write(f"**Pattern owner:** {p.get('owner','—')} · **Version:** {p.get('version','—')}")
                st.caption(p.get("source_note","Controlled knowledge base. Confirm asset applicability with the reviewer."))
            x,y=st.columns(2)
            with x:imp=st.select_slider("Impact",[1,2,3,4,5],value=risk(pid)["impact"],key="ni_"+pid)
            with y:fea=st.select_slider("Attack feasibility",[1,2,3,4,5],value=risk(pid)["feasibility"],key="nf_"+pid)
            st.session_state.nex_risks[pid]={"impact":imp,"feasibility":fea}
            ra=RiskEngine.calculate_risk(imp,fea);st.metric("Prototype risk score",f"{ra.score} / 25",f"{ra.band} · Impact {imp} × Feasibility {fea}")
            bundle=mitigator.draft_mitigation_bundle(pid,a["name"])
            tc, tr, tt=st.tabs([f"Controls · {len(bundle.controls)}",f"Requirements · {len(bundle.requirements)}","Verification"])
            with tc:
                for c in bundle.controls:st.markdown(f"**{c['id']} · {c['name']}**  \n{c['description']}")
            with tr:
                for req in bundle.requirements:st.markdown(f"**{req.id} · {req.title}**  \n{req.requirement_text}")
            with tt:
                seen=0
                for req in bundle.requirements:
                    for test in req.tests:
                        st.markdown(f"**{test['id']} · {test['title']}**  \n{test['objective']}");seen+=1
                        if seen>=6:break
                    if seen>=6:break
                if not seen:st.caption("No linked tests in the current pattern bundle.")
            p1,p2=st.columns(2)
            with p1:
                if st.button("Accept recommendation",key="yes_"+pid,type="primary",use_container_width=True):st.session_state.nex_decisions[pid]="Accepted";st.rerun()
            with p2:
                if st.button("Reject recommendation",key="no_"+pid,use_container_width=True):st.session_state.nex_decisions[pid]="Rejected";st.rerun()
            st.caption("Disposition: "+st.session_state.nex_decisions.get(pid,"Awaiting review")+" · Human reviewer retains acceptance authority.")
        else:st.info("No findings match these filters.")

elif page=="System model":
    head("ARCHITECTURE / CHANGE CONTROL","System model","Inspect modeled assets and interfaces, then identify the TARA impact of an architecture revision.")
    c=st.columns(4)
    for col,label,value,foot in zip(c,["Components","Interfaces","Boundaries","Data flows"],[len(analyzer.components),len(analyzer.interfaces),len(analyzer.trust_boundaries),len(analyzer.data_flows)],["System nodes","Communication links","Trust transitions","Modeled exchanges"]):
        with col:stat(label,value,foot)
    st.markdown("<div class='section'><div class='section-title'>Logical system path</div><div class='section-sub'>Primary remote control to vehicle network route</div><div class='timeline'><span class='node'>APP / USER</span><span class='connector'>TB-01</span><span class='node'>CLOUD SERVICES</span><span class='connector'>TB-02</span><span class='node'>TCU</span><span class='connector'>TB-03</span><span class='node'>GATEWAY</span><span class='connector'>CAN · ETHERNET</span><span class='node'>ECUS</span></div></div>",unsafe_allow_html=True)
    assets,interfaces,delta=st.tabs(["Asset exposure","Interface inventory","Revision impact"])
    with assets:
        rows=[]
        for aid,a in analyzer.assets.items():
            s=surfaces[aid];rows.append({"ID":aid,"Asset":a["name"],"Class":a["type"],"Interfaces":", ".join(s.interface_ids),"Trust boundaries":", ".join(s.trust_boundary_ids)})
        st.dataframe(pd.DataFrame(rows),hide_index=True,use_container_width=True)
    with interfaces:
        rows=[{"ID":i["id"],"Name":i["name"],"From":i["source_component_id"],"To":i["target_component_id"],"Protocol":i["protocol"],"Boundary":i["trust_boundary_id"]} for i in analyzer.interfaces.values()]
        st.dataframe(pd.DataFrame(rows),hide_index=True,use_container_width=True)
    with delta:
        old=loader.load_architecture("v1");new=loader.load_architecture("v2")
        oldc={x["id"]:x for x in old["components"]};newc={x["id"]:x for x in new["components"]};oldi={x["id"]:x for x in old["interfaces"]};newi={x["id"]:x for x in new["interfaces"]}
        addedc=set(newc)-set(oldc);addedi=set(newi)-set(oldi)
        st.markdown("**Revision 01 → Revision 02**")
        for cid in sorted(addedc):st.markdown(f"{badge('COMPONENT ADDED','due')} **{cid} · {newc[cid]['name']}** — {newc[cid]['description']}")
        for iid in sorted(addedi):st.markdown(f"{badge('INTERFACE ADDED','due')} **{iid} · {newi[iid]['name']}** — {newi[iid]['protocol']} crossing {newi[iid]['trust_boundary_id']}")
        relevant=[p for p in patterns if p.get("trust_boundary")=="TB-05"]
        st.markdown(f"#### Activated reassessment queue · {len(relevant)} patterns")
        for p in relevant:st.markdown(f"{p['id']} · {p['title']} &nbsp; {badge(p['freshness_status'],freshness(p))}")
        st.info("The wireless diagnostic adapter creates boundary TB-05. Review pairing and adapter exploitation scenarios in Revision 02.")

else:
    head("EVIDENCE / KNOWLEDGE CONTROL","Evidence & governance","Measure traceability and inspect the ownership and review lifecycle of the controlled knowledge set.")
    derived=loader.build_derived_traceability(kb["threat_patterns"],kb["controls"],kb["requirements"],kb["verification_tests"])
    rows=[];complete=0
    for p in patterns:
        cids=p.get("suggested_control_ids",[]);rids=set();tids=set()
        for cid in cids:rids.update(derived["control_to_requirements"].get(cid,[]))
        for rid in rids:tids.update(derived["requirement_to_tests"].get(rid,[]))
        ok=bool(cids and rids and tids);complete+=ok;aid,a=target_asset(p)
        rows.append({"Asset":a["name"],"Threat ID":p["id"],"Scenario":p["title"],"Controls":len(cids),"Requirements":len(rids),"Tests":len(tids),"Disposition":st.session_state.nex_decisions.get(p["id"],"Pending"),"Evidence chain":"Complete" if ok else "Incomplete"})
    m=st.columns(4)
    with m[0]:stat("Threat records",len(patterns),"Controlled library")
    with m[1]:stat("Chain coverage",f"{complete/len(rows):.0%}","Threat → control → requirement → test")
    with m[2]:stat("Controls",len(kb["controls"]),"Approved pattern references")
    with m[3]:stat("Review actions",sum(r["Disposition"]!="Pending" for r in rows),"Captured in this session")
    st.markdown("<div class='section'><div class='section-title'>Evidence path</div><div class='section-sub'>Forward links are explicit; reverse references are derived from the knowledge base</div><div class='timeline'><span class='node'>ASSET</span><span class='connector'>→</span><span class='node'>THREAT</span><span class='connector'>→</span><span class='node'>RISK</span><span class='connector'>→</span><span class='node'>CONTROL</span><span class='connector'>→</span><span class='node'>REQUIREMENT</span><span class='connector'>→</span><span class='node'>TEST</span><span class='connector'>→</span><span class='node'>REVIEW</span></div></div>",unsafe_allow_html=True)
    t1,t2=st.tabs(["Traceability register","Knowledge freshness"])
    with t1:
        st.dataframe(pd.DataFrame(rows),hide_index=True,use_container_width=True)
        export={"workspace":"NexTARA","baseline":baseline,"reference_date":"2026-10-13","records":rows}
        c1,c2=st.columns(2)
        with c1:st.download_button("Export register · CSV",pd.DataFrame(rows).to_csv(index=False),"nextara_traceability.csv","text/csv",use_container_width=True)
        with c2:st.download_button("Export assessment · JSON",json.dumps(export,indent=2),"nextara_assessment.json","application/json",use_container_width=True)
    with t2:
        search=st.text_input("Find knowledge pattern",placeholder="Title, ID, owner, boundary")
        due=st.toggle("Review due or outdated only")
        kbrows=[]
        for p in patterns:
            hay=" ".join([p["id"],p.get("title",""),p.get("owner",""),p.get("trust_boundary","")]).lower()
            if search.lower() not in hay or due and p["freshness_status"]=="Current":continue
            kbrows.append({"ID":p["id"],"Pattern":p["title"],"Boundary":p["trust_boundary"],"Owner":p.get("owner","—"),"Version":p.get("version","—"),"Last review":p.get("last_review_date","—"),"Next review":p.get("next_review_date","—"),"Status":p["freshness_status"]})
        st.dataframe(pd.DataFrame(kbrows),hide_index=True,use_container_width=True)
        st.caption("Current = more than 30 days ahead · Review Due = due within 30 days or overdue up to 180 days · Outdated = overdue by more than 180 days. Reference date: 13 Oct 2026.")

