"""Phase 3 Verification Tests: Independent testing of all 5 audit modules and scoring engine."""
import pytest
from app.auditors.permissions_auditor import FilePermissionAuditor
from app.auditors.security_auditor import SecurityConfigAuditor
from app.auditors.services_auditor import RunningServicesAuditor
from app.auditors.updates_auditor import SystemUpdateAuditor
from app.auditors.users_auditor import UserAccountAuditor
from app.core.powershell import run_powershell
from app.core.scoring import calculate_security_score, run_full_security_audit
from app.core.system_info import collect_system_info


def test_powershell_forbidden_verb_guard():
    """Ensure destructive PowerShell verbs are strictly blocked."""
    with pytest.raises(ValueError, match="forbidden verb"):
        run_powershell("Stop-Service -Name Spooler")


def test_system_info_collector():
    """Test real host system information collection."""
    info = collect_system_info()
    print(f"\n[SystemInfo] Host: {info.hostname} | OS: {info.os_name} (Build {info.os_build}) | User: {info.current_user} | Admin: {info.is_admin}")
    assert info.hostname != ""
    assert info.os_build != ""
    assert info.ram_total_gb > 0
    assert info.cpu_cores >= 1


def test_user_account_auditor():
    """Test Module B: User Account Auditor against actual Windows local accounts."""
    res = UserAccountAuditor().run_audit()
    print(f"\n[UsersAudit] Total Accounts: {res.total_accounts}, Enabled: {res.enabled_accounts}, Admins: {res.admin_accounts}")
    for c in res.checks:
        print(f"  - {c.check_id} ({c.title}): {c.status.value} [{c.severity.value}] -> {c.evidence}")
    assert res.total_accounts >= 1
    assert len(res.checks) == 7


def test_system_update_auditor():
    """Test Module C: System Update Auditor against actual Windows update status."""
    res = SystemUpdateAuditor().run_audit()
    print(f"\n[UpdatesAudit] OS: {res.os_caption} Build {res.os_build} | Installed Hotfixes: {len(res.installed_updates)} | Last Update: {res.last_update_date}")
    for c in res.checks:
        print(f"  - {c.check_id} ({c.title}): {c.status.value} [{c.severity.value}] -> {c.evidence}")
    assert res.os_build != ""
    assert len(res.checks) == 5


def test_file_permission_auditor():
    """Test Module D: File and Directory Permission Auditor against critical NTFS paths."""
    res = FilePermissionAuditor().run_audit()
    print(f"\n[PermissionsAudit] Inspected Paths: {res.inspected_paths_count} | Total ACEs: {len(res.entries)} | Risky ACEs: {res.risky_permissions_count}")
    for c in res.checks:
        print(f"  - {c.check_id} ({c.title}): {c.status.value} [{c.severity.value}] -> {c.evidence}")
    assert res.inspected_paths_count == 6
    assert len(res.entries) > 0
    assert len(res.checks) == 5


def test_running_services_auditor():
    """Test Module E: Running Services Auditor against Windows services."""
    res = RunningServicesAuditor().run_audit()
    print(f"\n[ServicesAudit] Total: {res.total_services}, Running: {res.running_services}, LocalSystem Running: {res.elevated_running_services}, Risky: {res.risky_services_count}")
    for c in res.checks:
        print(f"  - {c.check_id} ({c.title}): {c.status.value} [{c.severity.value}] -> {c.evidence}")
    assert res.total_services > 50
    assert res.running_services > 10
    assert len(res.checks) == 5


def test_security_config_auditor():
    """Test Module F: Security Configuration Auditor (Defender, Firewall, UAC, RDP, SecureBoot, BitLocker, SMBv1)."""
    res = SecurityConfigAuditor().run_audit()
    print(f"\n[SecurityConfigAudit] Controls Evaluated: {len(res.controls)}")
    for c in res.checks:
        print(f"  - {c.check_id} ({c.title}): {c.status.value} [{c.severity.value}] -> {c.evidence}")
    assert len(res.checks) == 9
    assert len(res.controls) == 9


def test_scoring_engine_and_full_audit():
    """Test the full audit orchestrator and 100-point scoring engine."""
    full_report = run_full_security_audit()
    score = full_report.score
    print(f"\n[ScoringEngine] Overall Score: {score.overall_score}/100 ({score.risk_rating}) in {full_report.duration_seconds}s")
    for cat_key, cat_val in score.categories.items():
        print(f"  * {cat_val.category_label}: {cat_val.earned_points}/{cat_val.max_points} pts ({cat_val.percentage}%)")
    assert 0.0 <= score.overall_score <= 100.0
    assert score.total_checks == 31
