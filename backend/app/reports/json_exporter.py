"""JSON Audit Report Exporter."""
from datetime import datetime, timezone
import json
from pathlib import Path

from app.schemas.audit_schemas import FullAuditResultSchema


def export_audit_to_json_file(
    audit_result: FullAuditResultSchema, output_dir: Path
) -> Path:
    """Export a FullAuditResultSchema to a formatted JSON file on disk."""
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_host = "".join(
        c if c.isalnum() or c in ("-", "_") else "_"
        for c in audit_result.system_info.hostname
    )
    filename = f"WinSecAudit_Report_{safe_host}_{audit_result.audit_id}.json"
    file_path = output_dir / filename

    actionable = [
        c.model_dump()
        for c in audit_result.all_checks
        if c.status.value in ("FAIL", "WARNING")
    ]

    export_payload = {
        "report_metadata": {
            "project_title": "Security Audit of a Computer System (WinSecAudit)",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "audit_id": audit_result.audit_id,
            "format": "JSON",
        },
        "executive_assessment": {
            "overall_score": audit_result.score.overall_score,
            "max_score": 100.0,
            "risk_rating": audit_result.score.risk_rating,
            "executive_summary": audit_result.score.executive_summary,
            "methodology": audit_result.score.methodology_notes,
        },
        "identified_vulnerabilities_and_weaknesses": actionable,
        "full_audit_data": audit_result.model_dump(),
    }

    file_path.write_text(
        json.dumps(export_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return file_path
