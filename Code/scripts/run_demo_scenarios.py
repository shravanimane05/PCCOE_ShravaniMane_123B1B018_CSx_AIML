"""Execute AutoTARA AI Phase 2 Demo Scenarios against pre-recorded expected outputs.

Implements six scenarios:
1. Token Abuse (A-01)
2. Malicious OTA Firmware (A-03)
3. Replayed Remote Command (A-07)
4. Compromised TCU CAN Injection (A-05)
5. Diagnostic Security-Access Bypass (A-08)
6. Bluetooth Adapter Change Impact (v1 vs v2 stub)
"""

import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Tuple

# Support running directly
code_dir = Path(__file__).resolve().parent.parent
if str(code_dir) not in sys.path:
    sys.path.insert(0, str(code_dir))

from autotara.architecture_analyzer import ArchitectureAnalyzer
from autotara.data_loader import DataLoader
from autotara.mitigation_engine import MitigationEngine
from autotara.retrieval.index_builder import IndexBuilder
from autotara.risk_engine import RiskEngine
from autotara.threat_engine import ThreatEngine


def run_scenarios(verbose: bool = True) -> Dict[str, Any]:
    loader = DataLoader()
    analyzer_v1 = ArchitectureAnalyzer.from_loader(loader, version="v1")
    analyzer_v2 = ArchitectureAnalyzer.from_loader(loader, version="v2")

    index_builder = IndexBuilder(loader=loader)
    threat_engine_v1 = ThreatEngine(analyzer=analyzer_v1, index_builder=index_builder, loader=loader)
    threat_engine_v2 = ThreatEngine(analyzer=analyzer_v2, index_builder=index_builder, loader=loader)
    mitigation_engine = MitigationEngine(loader=loader)

    expected_path = code_dir / "data" / "expected_demo_scenarios.json"
    with open(expected_path, "r", encoding="utf-8") as f:
        expected_data = json.load(f)

    scenario_results: Dict[str, Any] = {}

    # Scenario 1: Token Abuse (A-01)
    exp1 = expected_data["scenario_1_token_abuse"]
    t1 = threat_engine_v1.identify_threats_for_asset("A-01", mode="hybrid", top_k=3)
    top1 = t1.results[0] if t1.results else None
    mit1 = mitigation_engine.draft_mitigation_bundle(top1.pattern_id, "User Account & Access Token") if top1 else None
    risk1 = RiskEngine.calculate_risk(impact=4, attack_feasibility=4) # High risk
    c1_ids = [c["id"] for c in (mit1.controls if mit1 else [])]

    s1_match = (top1 is not None and top1.pattern_id == exp1["expected_top_threat_id"] and
                all(c in c1_ids for c in exp1["expected_controls_contain"]))
    scenario_results["scenario_1_token_abuse"] = {
        "name": exp1["name"],
        "expected_threat": exp1["expected_top_threat_id"],
        "actual_threat": top1.pattern_id if top1 else "NONE",
        "actual_title": top1.title if top1 else "NONE",
        "retrieval_mode": top1.retrieval_mode if top1 else "NONE",
        "score": top1.score if top1 else 0.0,
        "risk_band": risk1.band,
        "controls": c1_ids[:3],
        "passed": s1_match,
    }

    # Scenario 2: Malicious OTA Firmware (A-03)
    exp2 = expected_data["scenario_2_malicious_ota_firmware"]
    t2 = threat_engine_v1.identify_threats_for_asset("A-03", mode="hybrid", top_k=3)
    top2 = t2.results[0] if t2.results else None
    mit2 = mitigation_engine.draft_mitigation_bundle(top2.pattern_id, "OTA Firmware Package") if top2 else None
    risk2 = RiskEngine.calculate_risk(impact=5, attack_feasibility=3) # Critical risk
    c2_ids = [c["id"] for c in (mit2.controls if mit2 else [])]

    s2_match = (top2 is not None and top2.pattern_id == exp2["expected_top_threat_id"] and
                all(c in c2_ids for c in exp2["expected_controls_contain"]))
    scenario_results["scenario_2_malicious_ota_firmware"] = {
        "name": exp2["name"],
        "expected_threat": exp2["expected_top_threat_id"],
        "actual_threat": top2.pattern_id if top2 else "NONE",
        "actual_title": top2.title if top2 else "NONE",
        "retrieval_mode": top2.retrieval_mode if top2 else "NONE",
        "score": top2.score if top2 else 0.0,
        "risk_band": risk2.band,
        "controls": c2_ids[:3],
        "passed": s2_match,
    }

    # Scenario 3: Replayed Remote Command (A-07)
    exp3 = expected_data["scenario_3_replayed_remote_command"]
    t3 = threat_engine_v1.identify_threats_for_asset("A-07", mode="hybrid", top_k=5)
    # Check if expected threat is retrieved in top results
    t3_pids = [r.pattern_id for r in t3.results]
    top3 = t3.results[0] if t3.results else None
    # If TP-003 is top or in top-3
    s3_found = exp3["expected_top_threat_id"] in t3_pids
    mit3 = mitigation_engine.draft_mitigation_bundle(t3_pids[0], "CAN/Ethernet Messages") if t3_pids else None
    risk3 = RiskEngine.calculate_risk(impact=4, attack_feasibility=3)
    c3_ids = [c["id"] for c in (mit3.controls if mit3 else [])]

    scenario_results["scenario_3_replayed_remote_command"] = {
        "name": exp3["name"],
        "expected_threat": exp3["expected_top_threat_id"],
        "actual_threat": top3.pattern_id if top3 else "NONE",
        "actual_title": top3.title if top3 else "NONE",
        "top_retrieved": t3_pids[:3],
        "retrieval_mode": top3.retrieval_mode if top3 else "NONE",
        "score": top3.score if top3 else 0.0,
        "risk_band": risk3.band,
        "controls": c3_ids[:3],
        "passed": (top3.pattern_id == exp3["expected_top_threat_id"]) if top3 else False,
    }

    # Scenario 4: Compromised TCU CAN Injection (A-05)
    exp4 = expected_data["scenario_4_compromised_tcu_can_injection"]
    t4 = threat_engine_v1.identify_threats_for_asset("A-05", mode="hybrid", top_k=3)
    top4 = t4.results[0] if t4.results else None
    t4_pids = [r.pattern_id for r in t4.results]
    mit4 = mitigation_engine.draft_mitigation_bundle(top4.pattern_id, "TCU") if top4 else None
    risk4 = RiskEngine.calculate_risk(impact=5, attack_feasibility=4) # Critical
    c4_ids = [c["id"] for c in (mit4.controls if mit4 else [])]

    scenario_results["scenario_4_compromised_tcu_can_injection"] = {
        "name": exp4["name"],
        "expected_threat": exp4["expected_top_threat_id"],
        "actual_threat": top4.pattern_id if top4 else "NONE",
        "actual_title": top4.title if top4 else "NONE",
        "top_retrieved": t4_pids[:3],
        "retrieval_mode": top4.retrieval_mode if top4 else "NONE",
        "score": top4.score if top4 else 0.0,
        "risk_band": risk4.band,
        "controls": c4_ids[:3],
        "passed": (top4.pattern_id == exp4["expected_top_threat_id"]) if top4 else False,
    }

    # Scenario 5: Diagnostic Security Access Bypass (A-08)
    exp5 = expected_data["scenario_5_diagnostic_security_access_bypass"]
    t5 = threat_engine_v1.identify_threats_for_asset("A-08", mode="hybrid", top_k=3)
    top5 = t5.results[0] if t5.results else None
    mit5 = mitigation_engine.draft_mitigation_bundle(top5.pattern_id, "Diagnostic Services") if top5 else None
    risk5 = RiskEngine.calculate_risk(impact=4, attack_feasibility=3)
    c5_ids = [c["id"] for c in (mit5.controls if mit5 else [])]

    s5_match = (top5 is not None and top5.pattern_id == exp5["expected_top_threat_id"] and
                all(c in c5_ids for c in exp5["expected_controls_contain"]))
    scenario_results["scenario_5_diagnostic_security_access_bypass"] = {
        "name": exp5["name"],
        "expected_threat": exp5["expected_top_threat_id"],
        "actual_threat": top5.pattern_id if top5 else "NONE",
        "actual_title": top5.title if top5 else "NONE",
        "retrieval_mode": top5.retrieval_mode if top5 else "NONE",
        "score": top5.score if top5 else 0.0,
        "risk_band": risk5.band,
        "controls": c5_ids[:3],
        "passed": s5_match,
    }

    # Scenario 6: Bluetooth Adapter Change Impact (v1 vs v2 stub)
    exp6 = expected_data["scenario_6_bluetooth_adapter_change_impact"]
    # In v1: search for Bluetooth threats on A-08
    t6_v1 = threat_engine_v1.identify_threats_for_asset("A-08", mode="hybrid", top_k=10, baseline_version="v1")
    v1_pids = [r.pattern_id for r in t6_v1.results]
    v1_absent = exp6["baseline_v1_expected_absent_threat"] not in v1_pids

    # In v2: query specific to Bluetooth interface / diagnostic link
    bt_query = "Asset: Diagnostic Services and Session Access | Type: diagnostic_services | Protocols: Bluetooth SPP / OBD-II over CAN | Trust Boundaries: TB-05"
    results_v2 = index_builder.search(
        query=bt_query,
        mode="hybrid",
        top_k=3,
        asset_type="diagnostic_services",
        trust_boundary_ids=["TB-05"],
        baseline_version="v2",
        enable_filtering=True,
    )
    top6_v2 = results_v2[0] if results_v2 else None
    v2_pids = [r.pattern_id for r in results_v2]

    mit6 = mitigation_engine.draft_mitigation_bundle(top6_v2.pattern_id, "Diagnostic Services") if top6_v2 else None
    risk6 = RiskEngine.calculate_risk(impact=4, attack_feasibility=4)
    c6_ids = [c["id"] for c in (mit6.controls if mit6 else [])]

    s6_match = v1_absent and (top6_v2 is not None and top6_v2.pattern_id in ("TP-013", "TP-030"))
    scenario_results["scenario_6_bluetooth_adapter_change_impact"] = {
        "name": exp6["name"],
        "baseline_v1_absent_confirmed": v1_absent,
        "baseline_v2_top_threat": top6_v2.pattern_id if top6_v2 else "NONE",
        "baseline_v2_top_title": top6_v2.title if top6_v2 else "NONE",
        "retrieval_mode": top6_v2.retrieval_mode if top6_v2 else "NONE",
        "score": top6_v2.score if top6_v2 else 0.0,
        "risk_band": risk6.band,
        "controls": c6_ids[:3],
        "passed": s6_match,
    }

    if verbose:
        print("=" * 80)
        print("AutoTARA AI — Phase 2 Demo Scenarios Execution")
        print("=" * 80)
        for s_key, s_res in scenario_results.items():
            status_str = "PASS" if s_res.get("passed") else "MISMATCH / INVESTIGATE"
            print(f"[{status_str}] {s_res.get('name')}")
            print(f"  Expected: {s_res.get('expected_threat') or 'N/A'}")
            print(f"  Actual:   {s_res.get('actual_threat') or s_res.get('baseline_v2_top_threat')} - {s_res.get('actual_title') or s_res.get('baseline_v2_top_title')}")
            print(f"  Mode:     {s_res.get('retrieval_mode')} (Score: {s_res.get('score'):.4f})")
            print(f"  Risk:     {s_res.get('risk_band')}")
            print(f"  Controls: {s_res.get('controls')}")
            print("-" * 80)

    return scenario_results


if __name__ == "__main__":
    run_scenarios(verbose=True)
