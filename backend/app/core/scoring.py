"""Transparent 100-point security scoring engine and full audit orchestrator."""
from datetime import datetime, timezone
import time
import uuid
from typing import Dict, List

from app.auditors.permissions_auditor import FilePermissionAuditor
from app.auditors.security_auditor import SecurityConfigAuditor
from app.auditors.services_auditor import RunningServicesAuditor
from app.auditors.updates_auditor import SystemUpdateAuditor
from app.auditors.users_auditor import UserAccountAuditor
from app.config import CATEGORY_WEIGHTS
from app.core.system_info import collect_system_info
from app.schemas.audit_schemas import (
    AuditCategory,
    AuditCheckResult,
    CategoryScoreSummary,
    CheckStatus,
    FullAuditResultSchema,
    ScoreBreakdownResult,
    SeverityLevel,
)

SEVERITY_WEIGHTS: Dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 10.0,
    SeverityLevel.HIGH: 6.0,
    SeverityLevel.MEDIUM: 3.0,
    SeverityLevel.LOW: 1.0,
    SeverityLevel.INFORMATIONAL: 0.0,
}

CATEGORY_LABELS: Dict[str, str] = {
    AuditCategory.USER_ACCOUNTS.value: "User Accounts",
    AuditCategory.SYSTEM_UPDATES.value: "System Updates",
    AuditCategory.FILE_PERMISSIONS.value: "File Permissions",
    AuditCategory.RUNNING_SERVICES.value: "Running Services",
    AuditCategory.SECURITY_CONFIG.value: "Security Configurations",
}


def calculate_security_score(all_checks: List[AuditCheckResult]) -> ScoreBreakdownResult:
    """
    Calculate category-level and overall security posture score out of 100
    using actual check results.
    """
    categories_summary: Dict[str, CategoryScoreSummary] = {}
    overall_earned = 0.0

    for cat_enum in AuditCategory:
        cat_key = cat_enum.value
        max_pts = float(CATEGORY_WEIGHTS.get(cat_key, 20.0))
        cat_checks = [c for c in all_checks if c.category == cat_enum]

        passed = sum(1 for c in cat_checks if c.status == CheckStatus.PASS)
        failed = sum(1 for c in cat_checks if c.status == CheckStatus.FAIL)
        warnings = sum(1 for c in cat_checks if c.status == CheckStatus.WARNING)
        infos = sum(1 for c in cat_checks if c.status == CheckStatus.INFO)
        not_assessed = sum(1 for c in cat_checks if c.status == CheckStatus.NOT_ASSESSED)

        possible_weight = 0.0
        earned_weight = 0.0

        for chk in cat_checks:
            if chk.status in (CheckStatus.NOT_ASSESSED, CheckStatus.INFO):
                continue
            w = SEVERITY_WEIGHTS.get(chk.severity, 1.0)
            if w <= 0:
                continue
            possible_weight += w
            if chk.status == CheckStatus.PASS:
                earned_weight += w
            elif chk.status == CheckStatus.WARNING:
                earned_weight += w * 0.5
            # CheckStatus.FAIL earns 0.0

        if possible_weight > 0:
            ratio = earned_weight / possible_weight
            cat_earned = round(max_pts * ratio, 2)
            cat_pct = round(ratio * 100.0, 1)
        else:
            cat_earned = max_pts
            cat_pct = 100.0

        overall_earned += cat_earned

        categories_summary[cat_key] = CategoryScoreSummary(
            category=cat_enum,
            category_label=CATEGORY_LABELS.get(cat_key, cat_key),
            max_points=max_pts,
            earned_points=cat_earned,
            percentage=cat_pct,
            total_checks=len(cat_checks),
            passed_checks=passed,
            failed_checks=failed,
            warning_checks=warnings,
            info_checks=infos,
            not_assessed_checks=not_assessed,
        )

    overall_score = round(min(100.0, max(0.0, overall_earned)), 1)

    total_checks = len(all_checks)
    total_passed = sum(1 for c in all_checks if c.status == CheckStatus.PASS)
    total_failed = sum(1 for c in all_checks if c.status == CheckStatus.FAIL)
    total_warnings = sum(1 for c in all_checks if c.status == CheckStatus.WARNING)
    total_info = sum(1 for c in all_checks if c.status == CheckStatus.INFO)
    total_na = sum(1 for c in all_checks if c.status == CheckStatus.NOT_ASSESSED)

    # Count non-passing findings by severity
    actionable = [c for c in all_checks if c.status in (CheckStatus.FAIL, CheckStatus.WARNING)]
    crit_count = sum(1 for c in actionable if c.severity == SeverityLevel.CRITICAL)
    high_count = sum(1 for c in actionable if c.severity == SeverityLevel.HIGH)
    med_count = sum(1 for c in actionable if c.severity == SeverityLevel.MEDIUM)
    low_count = sum(1 for c in actionable if c.severity == SeverityLevel.LOW)

    if overall_score >= 85 and crit_count == 0:
        risk_rating = "Low Risk (Strong Posture)"
    elif overall_score >= 70 and crit_count == 0:
        risk_rating = "Moderate Risk (Acceptable with Hardening Needed)"
    elif overall_score >= 50:
        risk_rating = "Elevated Risk (Action Required)"
    else:
        risk_rating = "High / Critical Risk (Immediate Remediation Required)"

    exec_summary = (
        f"The Windows Security Audit evaluated {total_checks} security controls across 5 core domains, "
        f"achieving an overall security score of {overall_score}/100 ({risk_rating}). "
        f"In total, {total_passed} checks passed, {total_failed} failed, {total_warnings} raised warnings, "
        f"and {total_na} could not be assessed under the current privilege level. "
        f"Key areas requiring attention include {crit_count} Critical and {high_count} High severity findings."
    )

    methodology_notes = (
        "Scoring Allocation: User Accounts (20 pts), System Updates (20 pts), File Permissions (20 pts), "
        "Running Services (15 pts), Security Configurations (25 pts). "
        "Severity Weights: Critical=10, High=6, Medium=3, Low=1. "
        "PASS awards 100% of check weight, WARNING awards 50%, FAIL awards 0%. "
        "Checks marked NOT_ASSESSED (e.g., due to non-administrative privilege context) are excluded from the denominator."
    )

    return ScoreBreakdownResult(
        overall_score=overall_score,
        max_score=100.0,
        risk_rating=risk_rating,
        executive_summary=exec_summary,
        total_checks=total_checks,
        passed_checks=total_passed,
        failed_checks=total_failed,
        warning_checks=total_warnings,
        info_checks=total_info,
        not_assessed_checks=total_na,
        critical_findings_count=crit_count,
        high_findings_count=high_count,
        medium_findings_count=med_count,
        low_findings_count=low_count,
        categories=categories_summary,
        methodology_notes=methodology_notes,
    )


def run_full_security_audit() -> FullAuditResultSchema:
    """Execute all 5 Windows audit modules sequentially and compute the full security posture report."""
    start_ts = time.perf_counter()
    started_at = datetime.now(timezone.utc).isoformat()
    audit_id = f"AUD-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

    sys_info = collect_system_info()
    users_res = UserAccountAuditor().run_audit()
    updates_res = SystemUpdateAuditor().run_audit()
    perms_res = FilePermissionAuditor().run_audit()
    services_res = RunningServicesAuditor().run_audit()
    security_res = SecurityConfigAuditor().run_audit()

    all_checks: List[AuditCheckResult] = (
        users_res.checks
        + updates_res.checks
        + perms_res.checks
        + services_res.checks
        + security_res.checks
    )

    score_breakdown = calculate_security_score(all_checks)
    completed_at = datetime.now(timezone.utc).isoformat()
    duration_sec = round(time.perf_counter() - start_ts, 2)

    return FullAuditResultSchema(
        audit_id=audit_id,
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=duration_sec,
        system_info=sys_info,
        score=score_breakdown,
        all_checks=all_checks,
        users_module=users_res,
        updates_module=updates_res,
        permissions_module=perms_res,
        services_module=services_res,
        security_module=security_res,
    )
