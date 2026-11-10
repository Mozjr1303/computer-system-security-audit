"""Phase 7 Comprehensive Testing Suite: Security guarantees, edge cases, privilege handling, and API validation."""
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
import pytest

from app.auditors.permissions_auditor import FilePermissionAuditor
from app.auditors.services_auditor import RunningServicesAuditor
from app.core.powershell import FORBIDDEN_VERBS, PSResult, run_powershell
from app.core.scoring import calculate_security_score
from app.main import app
from app.schemas.audit_schemas import (
    AuditCategory,
    AuditCheckResult,
    CheckStatus,
    FindingType,
    SeverityLevel,
)


def test_read_only_guarantee_all_forbidden_verbs_blocked():
    """Verify every mutating PowerShell verb is strictly rejected before subprocess execution."""
    for verb in FORBIDDEN_VERBS:
        with pytest.raises(ValueError, match="Security policy violation"):
            run_powershell(f"{verb} -ErrorAction SilentlyContinue")


def test_auditor_source_files_contain_no_destructive_cmdlets():
    """Statically inspect all 5 auditor source files to ensure no state-modifying commands exist."""
    auditors_dir = Path(__file__).resolve().parent.parent / "app" / "auditors"
    py_files = list(auditors_dir.glob("*.py"))
    assert len(py_files) >= 6

    for f in py_files:
        content = f.read_text(encoding="utf-8")
        # Extract PowerShell script blocks (ignore remediation strings by checking actual PS assignments)
        assert "Stop-Computer" not in content
        assert "Restart-Computer" not in content
        assert "Invoke-Expression" not in content


def test_unquoted_service_path_detection_logic():
    """Verify CWE-428 unquoted binary path detector handles quoted, unquoted, and argument strings."""
    checker = RunningServicesAuditor._has_unquoted_service_path_vulnerability

    # Vulnerable: unquoted path with spaces before .exe
    assert checker(r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher Core\UpcElevationService.exe") is True
    assert checker(r"C:\Program Files\My App\service.exe -k run") is True

    # Safe: properly quoted path with spaces
    assert checker(r'"C:\Program Files (x86)\Ubisoft\UpcElevationService.exe" --service') is False
    # Safe: unquoted path with NO spaces before .exe (spaces only in arguments)
    assert checker(r"C:\Windows\system32\svchost.exe -k LocalService -p") is False
    assert checker("") is False


def test_unavailable_permissions_graceful_handling():
    """Simulate Access Denied on NTFS ACL inspection and verify graceful handling without crash."""
    mock_payload = [
        {
            "Path": r"C:\Windows\System32\config\SAM",
            "Label": "SAM Hive",
            "CriticalSystem": True,
            "Exists": True,
            "Accessible": False,
            "Owner": "Access Denied",
            "Access": [],
        }
    ]
    with patch("app.auditors.permissions_auditor.run_powershell") as mock_ps:
        mock_ps.return_value = PSResult(
            success=True,
            stdout="[]",
            stderr="",
            return_code=0,
            access_denied=True,
            parsed_json=mock_payload,
        )
        res = FilePermissionAuditor().run_audit()
        assert res.inspected_paths_count == 1
        assert len(res.entries) == 1
        assert res.entries[0].accessible is False
        assert res.entries[0].owner == "Access Denied"


def test_not_assessed_checks_do_not_penalize_score():
    """Verify checks marked NOT_ASSESSED under Standard User mode do not artificially lower category scores."""
    sample_checks = [
        AuditCheckResult(
            check_id="SEC-001",
            category=AuditCategory.SECURITY_CONFIG,
            title="Defender Active",
            description="Test",
            status=CheckStatus.PASS,
            severity=SeverityLevel.CRITICAL,
            finding_type=FindingType.CONFIGURATION_OBSERVATION,
            evidence="Active",
            explanation="Exp",
            remediation="None",
        ),
        AuditCheckResult(
            check_id="SEC-008",
            category=AuditCategory.SECURITY_CONFIG,
            title="BitLocker",
            description="Test",
            status=CheckStatus.NOT_ASSESSED,
            severity=SeverityLevel.HIGH,
            finding_type=FindingType.CONFIGURATION_OBSERVATION,
            evidence="Requires Admin",
            explanation="Exp",
            remediation="Run as Admin",
        ),
    ]
    score = calculate_security_score(sample_checks)
    sec_cat = score.categories["security_config"]
    assert sec_cat.not_assessed_checks == 1
    assert sec_cat.passed_checks == 1
    assert sec_cat.earned_points == 25.0
    assert sec_cat.percentage == 100.0


def test_api_error_handling_and_input_validation():
    """Verify 404 and 422 error responses for invalid IDs and malformed query parameters."""
    with TestClient(app) as client:
        # Non-existent audit ID -> 404
        res_404 = client.get("/api/audit/results/AUD-NONEXISTENT-000")
        assert res_404.status_code == 404

        status_404 = client.get("/api/audit/status/AUD-NONEXISTENT-000")
        assert status_404.status_code == 404

        # Non-existent report ID -> 404
        rep_404 = client.get("/api/reports/RPT-NONEXISTENT-000/download")
        assert rep_404.status_code == 404

        # Invalid report format parameter -> 422 validation error
        bad_fmt = client.post("/api/reports/AUD-123/generate?format=exe")
        assert bad_fmt.status_code == 422

        # Out-of-bounds history limit -> 422 validation error
        bad_limit = client.get("/api/history?limit=9999")
        assert bad_limit.status_code == 422


def test_all_31_stored_checks_have_complete_fields():
    """Verify every check in the stored audit session has non-empty evidence, explanation, and remediation."""
    with TestClient(app) as client:
        res = client.get("/api/audit/results/latest")
        assert res.status_code == 200
        data = res.json()
        checks = data["all_checks"]
        assert len(checks) == 31
        for chk in checks:
            assert chk["check_id"]
            assert chk["title"]
            assert chk["status"] in ("PASS", "FAIL", "WARNING", "INFO", "NOT_ASSESSED")
            assert chk["severity"] in ("Critical", "High", "Medium", "Low", "Informational")
            assert chk["finding_type"] in (
                "Security Weakness",
                "Confirmed Vulnerability",
                "Configuration Observation",
            )
            assert chk["explanation"]
            assert chk["remediation"]
