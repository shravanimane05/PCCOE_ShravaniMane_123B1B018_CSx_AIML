"""Structured TARA report generation for AutoTARA AI.

Assembles architecture, threat, risk, mitigation, traceability, review, and
audit sections into a single JSON document plus CSV extracts for export.
"""

import csv
import io
import json
from datetime import datetime
from typing import Any, Dict, List, Optional


REPORT_SCHEMA_VERSION = "1.0"


def build_report(
    project_name: str,
    baseline_version: str,
    baseline_name: str,
    generated_by: str,
    role: str,
    assets: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    traceability: Dict[str, Any],
    validation: Dict[str, Any],
    freshness: List[Dict[str, Any]],
    audit: List[Dict[str, Any]],
    decisions: Dict[str, Any],
    change_impact: Optional[Dict[str, Any]] = None,
    approval: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Assemble the complete structured TARA report payload."""
    report: Dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": "Automotive Cybersecurity TARA (prototype)",
        "project": project_name,
        "baseline": {"version": baseline_version, "name": baseline_name},
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "generated_by": generated_by or "Unattributed",
        "role": role,
        "disclaimer": (
            "Prototype TARA work product prepared with AI assistance. "
            "Risk acceptance remains with the authorized cybersecurity reviewer. "
            "Not an organization-approved ISO/SAE 21434 assessment."
        ),
        "asset_inventory": assets,
        "findings": findings,
        "traceability": traceability,
        "data_validation": validation,
        "threat_knowledge_freshness": freshness,
        "review_decisions": decisions,
        "audit_log": audit,
        "approval": approval or {"approved": False, "reason": "Not approved."},
    }
    if change_impact is not None:
        report["change_impact"] = change_impact
    return report


def report_to_json(report: Dict[str, Any]) -> str:
    """Serialize the report as pretty-printed JSON."""
    return json.dumps(report, indent=2, ensure_ascii=False)


def _csv_from_rows(headers: List[str], rows: List[List[Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(headers)
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()


def findings_to_csv(findings: List[Dict[str, Any]]) -> str:
    """Flatten review findings into a single CSV table."""
    headers = [
        "asset_id",
        "asset_name",
        "threat_id",
        "threat_title",
        "stride",
        "trust_boundary",
        "retrieval_mode",
        "retrieval_score",
        "confidence",
        "impact",
        "attack_feasibility",
        "risk_score",
        "risk_band",
        "controls",
        "requirements",
        "verification_tests",
        "decision",
        "reviewer",
        "decision_comment",
    ]
    rows = [
        [
            f.get("asset_id", ""),
            f.get("asset_name", ""),
            f.get("threat_id", ""),
            f.get("threat_title", ""),
            f.get("stride_category", ""),
            f.get("trust_boundary", ""),
            f.get("retrieval_mode", ""),
            f.get("retrieval_score", ""),
            f.get("confidence_label", ""),
            f.get("impact", ""),
            f.get("attack_feasibility", ""),
            f.get("risk_score", ""),
            f.get("risk_band", ""),
            "; ".join(f.get("controls", [])),
            "; ".join(f.get("requirements", [])),
            "; ".join(f.get("tests", [])),
            f.get("decision_status", ""),
            f.get("decision_reviewer", ""),
            f.get("decision_comment", ""),
        ]
        for f in findings
    ]
    return _csv_from_rows(headers, rows)


def traceability_to_csv(edges: List[Dict[str, Any]]) -> str:
    """Export the traceability edge list as CSV."""
    headers = ["source_id", "source_type", "relation", "target_id", "target_type", "name"]
    rows = [
        [
            e.get("source_id", ""),
            e.get("source_type", ""),
            e.get("relation", "links_to"),
            e.get("target_id", ""),
            e.get("target_type", ""),
            e.get("name", ""),
        ]
        for e in edges
    ]
    return _csv_from_rows(headers, rows)


def freshness_to_csv(rows: List[Dict[str, Any]]) -> str:
    """Export threat-knowledge freshness status as CSV."""
    headers = [
        "pattern_id",
        "title",
        "owner",
        "version",
        "last_review_date",
        "next_review_date",
        "days_ahead",
        "status",
    ]
    values = [
        [
            r.get("pattern_id", ""),
            r.get("title", ""),
            r.get("owner", ""),
            r.get("version", ""),
            r.get("last_review_date", ""),
            r.get("next_review_date", ""),
            r.get("days_ahead", ""),
            r.get("status", ""),
        ]
        for r in rows
    ]
    return _csv_from_rows(headers, values)
