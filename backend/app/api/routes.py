"""REST API endpoints for the Windows Security Audit System."""
from datetime import datetime, timezone
from pathlib import Path
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.auditors.permissions_auditor import FilePermissionAuditor
from app.auditors.security_auditor import SecurityConfigAuditor
from app.auditors.services_auditor import RunningServicesAuditor
from app.auditors.updates_auditor import SystemUpdateAuditor
from app.auditors.users_auditor import UserAccountAuditor
from app.config import REPORTS_DIR
from app.core.persistence import (
    get_audit_result_by_id,
    get_latest_audit_result,
    get_report_by_id,
    list_audit_history,
    list_reports,
    save_audit_result,
    save_report_metadata,
)
from app.core.scoring import run_full_security_audit
from app.core.system_info import collect_system_info
from app.database import get_db
from app.schemas.audit_schemas import (
    FullAuditResultSchema,
    PermissionAuditModuleResult,
    SecurityConfigModuleResult,
    ServiceAuditModuleResult,
    SystemInfoSchema,
    UpdateAuditModuleResult,
    UserAuditModuleResult,
)

router = APIRouter(prefix="/api")


@router.get("/system/info", response_model=SystemInfoSchema, tags=["System"])
def api_get_system_info():
    """Collect real-time host computer, OS, CPU, RAM, and privilege level information."""
    return collect_system_info()


@router.post("/audit/start", response_model=FullAuditResultSchema, tags=["Audit"])
def api_start_audit(db: Session = Depends(get_db)):
    """Execute a complete 5-module security audit on the host computer and store results in SQLite."""
    result = run_full_security_audit()
    save_audit_result(db, result)
    return result


@router.get("/audit/status/{audit_id}", tags=["Audit"])
def api_get_audit_status(audit_id: str, db: Session = Depends(get_db)):
    """Retrieve status and summary metrics for a specific audit session."""
    result = get_audit_result_by_id(db, audit_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Audit session '{audit_id}' not found.")
    return {
        "audit_id": result.audit_id,
        "status": "COMPLETED",
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "duration_seconds": result.duration_seconds,
        "overall_score": result.score.overall_score,
        "risk_rating": result.score.risk_rating,
        "total_checks": result.score.total_checks,
        "passed_checks": result.score.passed_checks,
        "failed_checks": result.score.failed_checks,
        "warning_checks": result.score.warning_checks,
    }


@router.get("/audit/results/latest", response_model=FullAuditResultSchema, tags=["Audit"])
def api_get_latest_audit_results(db: Session = Depends(get_db)):
    """Return the most recently completed security audit session."""
    result = get_latest_audit_result(db)
    if not result:
        raise HTTPException(
            status_code=404,
            detail="No security audit has been executed yet. Start a new audit first.",
        )
    return result


@router.get("/audit/results/{audit_id}", response_model=FullAuditResultSchema, tags=["Audit"])
def api_get_audit_results(audit_id: str, db: Session = Depends(get_db)):
    """Return full security audit results for a given audit_id."""
    result = get_audit_result_by_id(db, audit_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Audit session '{audit_id}' not found.")
    return result


@router.get("/audit/users", response_model=UserAuditModuleResult, tags=["Modules"])
def api_get_users_audit(
    refresh: bool = Query(default=False, description="Run a live standalone scan instead of using cached latest audit"),
    db: Session = Depends(get_db),
):
    """Get User Account Audit results (from latest audit session or live scan if refresh=true)."""
    if not refresh:
        latest = get_latest_audit_result(db)
        if latest:
            return latest.users_module
    return UserAccountAuditor().run_audit()


@router.get("/audit/updates", response_model=UpdateAuditModuleResult, tags=["Modules"])
def api_get_updates_audit(
    refresh: bool = Query(default=False, description="Run a live standalone scan instead of using cached latest audit"),
    db: Session = Depends(get_db),
):
    """Get System Update Audit results (from latest audit session or live scan if refresh=true)."""
    if not refresh:
        latest = get_latest_audit_result(db)
        if latest:
            return latest.updates_module
    return SystemUpdateAuditor().run_audit()


@router.get("/audit/permissions", response_model=PermissionAuditModuleResult, tags=["Modules"])
def api_get_permissions_audit(
    refresh: bool = Query(default=False, description="Run a live standalone scan instead of using cached latest audit"),
    db: Session = Depends(get_db),
):
    """Get File and Permission Audit results (from latest audit session or live scan if refresh=true)."""
    if not refresh:
        latest = get_latest_audit_result(db)
        if latest:
            return latest.permissions_module
    return FilePermissionAuditor().run_audit()


@router.get("/audit/services", response_model=ServiceAuditModuleResult, tags=["Modules"])
def api_get_services_audit(
    refresh: bool = Query(default=False, description="Run a live standalone scan instead of using cached latest audit"),
    db: Session = Depends(get_db),
):
    """Get Running Services Audit results (from latest audit session or live scan if refresh=true)."""
    if not refresh:
        latest = get_latest_audit_result(db)
        if latest:
            return latest.services_module
    return RunningServicesAuditor().run_audit()


@router.get("/audit/security", response_model=SecurityConfigModuleResult, tags=["Modules"])
def api_get_security_audit(
    refresh: bool = Query(default=False, description="Run a live standalone scan instead of using cached latest audit"),
    db: Session = Depends(get_db),
):
    """Get Security Configuration Audit results (from latest audit session or live scan if refresh=true)."""
    if not refresh:
        latest = get_latest_audit_result(db)
        if latest:
            return latest.security_module
    return SecurityConfigAuditor().run_audit()


@router.get("/history", tags=["History"])
def api_get_audit_history(
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Return historical security audit sessions stored in SQLite."""
    return {"items": list_audit_history(db, limit=limit)}


@router.get("/reports", tags=["Reports"])
def api_list_reports(db: Session = Depends(get_db)):
    """List all generated PDF and JSON audit reports."""
    return {"items": list_reports(db)}


@router.post("/reports/{audit_id}/generate", tags=["Reports"])
def api_generate_report(
    audit_id: str,
    format: str = Query(default="pdf", pattern="^(pdf|json)$"),
    db: Session = Depends(get_db),
):
    """Generate a PDF or JSON report for a completed audit session and record its metadata."""
    audit_res = get_audit_result_by_id(db, audit_id)
    if not audit_res:
        raise HTTPException(status_code=404, detail=f"Audit session '{audit_id}' not found.")

    now_iso = datetime.now(timezone.utc).isoformat()
    report_id = f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:5].upper()}"

    if format.lower() == "json":
        from app.reports.json_exporter import export_audit_to_json_file
        file_path = export_audit_to_json_file(audit_res, REPORTS_DIR)
        r_type = "JSON"
        title = f"Windows Security Audit JSON Export ({audit_res.system_info.hostname})"
    else:
        from app.reports.pdf_generator import generate_audit_pdf_report
        file_path = generate_audit_pdf_report(audit_res, REPORTS_DIR)
        r_type = "PDF"
        title = f"Windows Security Audit Report ({audit_res.system_info.hostname})"

    size_bytes = file_path.stat().st_size if file_path.exists() else 0

    meta = save_report_metadata(
        db=db,
        report_id=report_id,
        audit_id=audit_id,
        report_type=r_type,
        title=title,
        hostname=audit_res.system_info.hostname,
        overall_score=audit_res.score.overall_score,
        file_name=file_path.name,
        file_path=str(file_path.resolve()),
        file_size_bytes=size_bytes,
        created_at=now_iso,
    )
    return {
        "report_id": meta.report_id,
        "audit_id": meta.audit_id,
        "report_type": meta.report_type,
        "title": meta.title,
        "file_name": meta.file_name,
        "file_size_bytes": meta.file_size_bytes,
        "created_at": meta.created_at,
        "download_url": f"/api/reports/{meta.report_id}/download",
    }


@router.get("/reports/{report_id}/download", tags=["Reports"])
def api_download_report(report_id: str, db: Session = Depends(get_db)):
    """Download a previously generated PDF or JSON report file."""
    meta = get_report_by_id(db, report_id)
    if not meta:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")

    path = Path(meta.file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report file is missing on disk.")

    media_type = "application/pdf" if meta.report_type.upper() == "PDF" else "application/json"
    return FileResponse(
        path=str(path),
        media_type=media_type,
        filename=meta.file_name,
    )
