"""Database persistence service for storing and querying security audit sessions."""
import json
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.audit_models import (
    AuditFindingModel,
    AuditSessionModel,
    CategoryScoreModel,
    ReportMetadataModel,
)
from app.schemas.audit_schemas import FullAuditResultSchema


def save_audit_result(db: Session, result: FullAuditResultSchema) -> AuditSessionModel:
    """Persist a full security audit session, its category scores, and all individual findings."""
    existing = (
        db.query(AuditSessionModel)
        .filter(AuditSessionModel.audit_id == result.audit_id)
        .first()
    )
    if existing:
        return existing

    session_row = AuditSessionModel(
        audit_id=result.audit_id,
        status="COMPLETED",
        started_at=result.started_at,
        completed_at=result.completed_at,
        duration_seconds=result.duration_seconds,
        hostname=result.system_info.hostname,
        os_name=result.system_info.os_name,
        os_build=result.system_info.os_build,
        current_user=result.system_info.current_user,
        is_admin=result.system_info.is_admin,
        overall_score=result.score.overall_score,
        risk_rating=result.score.risk_rating,
        executive_summary=result.score.executive_summary,
        total_checks=result.score.total_checks,
        passed_checks=result.score.passed_checks,
        failed_checks=result.score.failed_checks,
        warning_checks=result.score.warning_checks,
        not_assessed_checks=result.score.not_assessed_checks,
        critical_count=result.score.critical_findings_count,
        high_count=result.score.high_findings_count,
        medium_count=result.score.medium_findings_count,
        low_count=result.score.low_findings_count,
        full_result_json=result.model_dump_json(),
    )
    db.add(session_row)

    for cat_key, cat_summary in result.score.categories.items():
        cat_row = CategoryScoreModel(
            audit_id=result.audit_id,
            category=cat_key,
            category_label=cat_summary.category_label,
            max_points=cat_summary.max_points,
            earned_points=cat_summary.earned_points,
            percentage=cat_summary.percentage,
            total_checks=cat_summary.total_checks,
            passed_checks=cat_summary.passed_checks,
            failed_checks=cat_summary.failed_checks,
            warning_checks=cat_summary.warning_checks,
            not_assessed_checks=cat_summary.not_assessed_checks,
        )
        db.add(cat_row)

    for chk in result.all_checks:
        finding_row = AuditFindingModel(
            audit_id=result.audit_id,
            check_id=chk.check_id,
            category=chk.category.value,
            title=chk.title,
            description=chk.description,
            status=chk.status.value,
            severity=chk.severity.value,
            finding_type=chk.finding_type.value,
            evidence=chk.evidence,
            explanation=chk.explanation,
            remediation=chk.remediation,
        )
        db.add(finding_row)

    db.commit()
    db.refresh(session_row)
    return session_row


def get_audit_result_by_id(db: Session, audit_id: str) -> Optional[FullAuditResultSchema]:
    """Load and deserialize a stored FullAuditResultSchema by audit_id."""
    row = (
        db.query(AuditSessionModel)
        .filter(AuditSessionModel.audit_id == audit_id)
        .first()
    )
    if not row:
        return None
    data = json.loads(row.full_result_json)
    return FullAuditResultSchema.model_validate(data)


def get_latest_audit_result(db: Session) -> Optional[FullAuditResultSchema]:
    """Retrieve the most recent completed audit session from SQLite."""
    row = (
        db.query(AuditSessionModel)
        .order_by(AuditSessionModel.id.desc())
        .first()
    )
    if not row:
        return None
    data = json.loads(row.full_result_json)
    return FullAuditResultSchema.model_validate(data)


def list_audit_history(db: Session, limit: int = 50) -> List[Dict[str, Any]]:
    """Return a chronological list of audit sessions and their category scores."""
    rows = (
        db.query(AuditSessionModel)
        .order_by(AuditSessionModel.id.desc())
        .limit(limit)
        .all()
    )
    history: List[Dict[str, Any]] = []
    for r in rows:
        cat_map = {
            c.category: {
                "category_label": c.category_label,
                "earned_points": c.earned_points,
                "max_points": c.max_points,
                "percentage": c.percentage,
            }
            for c in r.category_scores
        }
        history.append(
            {
                "audit_id": r.audit_id,
                "status": r.status,
                "started_at": r.started_at,
                "completed_at": r.completed_at,
                "duration_seconds": r.duration_seconds,
                "hostname": r.hostname,
                "os_name": r.os_name,
                "os_build": r.os_build,
                "current_user": r.current_user,
                "is_admin": r.is_admin,
                "overall_score": r.overall_score,
                "risk_rating": r.risk_rating,
                "total_checks": r.total_checks,
                "passed_checks": r.passed_checks,
                "failed_checks": r.failed_checks,
                "warning_checks": r.warning_checks,
                "not_assessed_checks": r.not_assessed_checks,
                "critical_count": r.critical_count,
                "high_count": r.high_count,
                "medium_count": r.medium_count,
                "low_count": r.low_count,
                "categories": cat_map,
            }
        )
    return history


def save_report_metadata(
    db: Session,
    report_id: str,
    audit_id: str,
    report_type: str,
    title: str,
    hostname: str,
    overall_score: float,
    file_name: str,
    file_path: str,
    file_size_bytes: int,
    created_at: str,
) -> ReportMetadataModel:
    """Record a generated PDF or JSON report in SQLite."""
    row = ReportMetadataModel(
        report_id=report_id,
        audit_id=audit_id,
        report_type=report_type,
        title=title,
        hostname=hostname,
        overall_score=overall_score,
        file_name=file_name,
        file_path=file_path,
        file_size_bytes=file_size_bytes,
        created_at=created_at,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_reports(db: Session) -> List[Dict[str, Any]]:
    """List all generated reports ordered newest first."""
    rows = (
        db.query(ReportMetadataModel)
        .order_by(ReportMetadataModel.id.desc())
        .all()
    )
    return [
        {
            "report_id": r.report_id,
            "audit_id": r.audit_id,
            "report_type": r.report_type,
            "title": r.title,
            "hostname": r.hostname,
            "overall_score": r.overall_score,
            "file_name": r.file_name,
            "file_size_bytes": r.file_size_bytes,
            "created_at": r.created_at,
        }
        for r in rows
    ]


def get_report_by_id(db: Session, report_id: str) -> Optional[ReportMetadataModel]:
    """Retrieve a single report metadata row by report_id."""
    return (
        db.query(ReportMetadataModel)
        .filter(ReportMetadataModel.report_id == report_id)
        .first()
    )
