"""Module E: Windows Running Services & Privilege Escalation Auditor."""
from typing import Dict, List
from app.auditors.base import BaseAuditor
from app.core.powershell import run_powershell
from app.schemas.audit_schemas import (
    AuditCategory,
    CheckStatus,
    FindingType,
    ServiceAuditModuleResult,
    ServiceItemDetail,
    SeverityLevel,
)

# Known high-risk or legacy services that should normally be disabled on hardened workstations
RISKY_SERVICES_CATALOG: Dict[str, Dict[str, str]] = {
    "remoteregistry": {
        "severity": "High",
        "reason": "Allows remote users to read and modify the Windows Registry over the network.",
        "remediation": "Disable the Remote Registry service unless explicitly required by enterprise management tools.",
    },
    "tlntsvr": {
        "severity": "Critical",
        "reason": "Telnet transmits credentials and session data in cleartext over the network.",
        "remediation": "Stop and disable the Telnet Server service; use SSH or WinRM with HTTPS instead.",
    },
    "simptcp": {
        "severity": "High",
        "reason": "Simple TCP/IP services (Echo, Daytime, Chargen) are susceptible to amplification and DoS attacks.",
        "remediation": "Disable Simple TCP/IP Services.",
    },
    "snmp": {
        "severity": "Medium",
        "reason": "SNMP service can expose detailed host configuration via default community strings.",
        "remediation": "Disable SNMP service if not required, or restrict to SNMPv3 with strong authentication.",
    },
    "ftpsvc": {
        "severity": "High",
        "reason": "Microsoft FTP Service can expose local files and cleartext credentials if not strictly configured with TLS.",
        "remediation": "Disable FTP service unless this machine is an authorized file server.",
    },
    "fax": {
        "severity": "Low",
        "reason": "Legacy Windows Fax service increases attack surface unnecessarily on modern endpoints.",
        "remediation": "Disable the Fax service if not in use.",
    },
    "spooler": {
        "severity": "Medium",
        "reason": "Print Spooler runs as SYSTEM and has historically been targeted by PrintNightmare (CVE-2021-34527) local/remote privilege escalation.",
        "remediation": "If printing is not needed on this host, consider disabling Print Spooler or disabling inbound remote printing via Group Policy.",
    },
}


class RunningServicesAuditor(BaseAuditor):
    """Inspects Windows services for unquoted binary paths, LocalSystem elevation risks, and risky running services."""

    category = AuditCategory.RUNNING_SERVICES

    def run_audit(self) -> ServiceAuditModuleResult:
        ps_script = """
        Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                Name = [string]$_.Name
                DisplayName = [string]$_.DisplayName
                State = [string]$_.State
                StartMode = [string]$_.StartMode
                StartName = [string]$_.StartName
                PathName = [string]$_.PathName
                ProcessId = [int]$_.ProcessId
            }
        }
        """
        res = run_powershell(ps_script, timeout=25, expect_json=True)
        raw_services = res.parsed_json if isinstance(res.parsed_json, list) else (
            [res.parsed_json] if isinstance(res.parsed_json, dict) else []
        )

        services: List[ServiceItemDetail] = []
        for s in raw_services:
            name = str(s.get("Name") or "")
            display_name = str(s.get("DisplayName") or name)
            state = str(s.get("State") or "Unknown")
            start_mode = str(s.get("StartMode") or "Unknown")
            start_name = str(s.get("StartName") or "LocalSystem")
            path_name = str(s.get("PathName") or "").strip()
            pid = int(s.get("ProcessId") or 0)

            sn_lower = start_name.lower()
            is_elevated = any(
                k in sn_lower for k in ("localsystem", "nt authority\\system", "system")
            )

            has_unquoted = self._has_unquoted_service_path_vulnerability(path_name)
            catalog_entry = RISKY_SERVICES_CATALOG.get(name.lower())
            is_running = state.lower() == "running"

            is_risky = False
            risk_level = SeverityLevel.INFORMATIONAL
            explanations: List[str] = []
            recommendations: List[str] = []

            if has_unquoted:
                is_risky = True
                risk_level = SeverityLevel.HIGH if is_elevated else SeverityLevel.MEDIUM
                explanations.append(
                    f"Service binary path '{path_name}' contains spaces and is not enclosed in quotes (CWE-428 Unquoted Search Path)."
                )
                recommendations.append(
                    f"Enclose the executable path in double quotes in HKLM:\\SYSTEM\\CurrentControlSet\\Services\\{name}\\ImagePath."
                )

            if catalog_entry and is_running:
                is_risky = True
                cat_sev = SeverityLevel(catalog_entry["severity"])
                if risk_level == SeverityLevel.INFORMATIONAL or cat_sev == SeverityLevel.CRITICAL:
                    risk_level = cat_sev
                explanations.append(catalog_entry["reason"])
                recommendations.append(catalog_entry["remediation"])

            # Flag third-party auto-start services running as LocalSystem outside C:\Windows
            if (
                is_running
                and is_elevated
                and path_name
                and "c:\\windows" not in path_name.lower()
                and not is_risky
            ):
                risk_level = SeverityLevel.LOW
                explanations.append(
                    "Third-party service running with highest LocalSystem privileges outside C:\\Windows."
                )
                recommendations.append(
                    "Verify the vendor binary signature and consider running under LocalService or a dedicated Virtual Service Account."
                )

            if not explanations:
                explanations.append("Standard Windows service configuration.")
                recommendations.append("No action required.")

            services.append(
                ServiceItemDetail(
                    name=name,
                    display_name=display_name,
                    state=state,
                    start_mode=start_mode,
                    start_name=start_name,
                    path_name=path_name,
                    process_id=pid,
                    is_elevated_system=is_elevated,
                    has_unquoted_path_risk=has_unquoted,
                    is_risky_service=is_risky,
                    risk_level=risk_level,
                    risk_explanation=" ".join(explanations),
                    recommendation=" ".join(recommendations),
                )
            )

        # Sort risky services first, then running services
        services.sort(
            key=lambda x: (not x.is_risky_service, x.state.lower() != "running", x.display_name.lower())
        )

        total_count = len(services)
        running_count = sum(1 for s in services if s.state.lower() == "running")
        stopped_count = sum(1 for s in services if s.state.lower() == "stopped")
        elevated_running = sum(1 for s in services if s.state.lower() == "running" and s.is_elevated_system)
        risky_count = sum(1 for s in services if s.is_risky_service)

        checks = self._evaluate_checks(services, total_count, running_count, elevated_running)

        return ServiceAuditModuleResult(
            checks=checks,
            total_services=total_count,
            running_services=running_count,
            stopped_services=stopped_count,
            elevated_running_services=elevated_running,
            risky_services_count=risky_count,
            services=services,
        )

    @staticmethod
    def _has_unquoted_service_path_vulnerability(path_name: str) -> bool:
        """
        Detect CWE-428 Unquoted Service Path vulnerability:
        A service path that is not enclosed in quotes and has spaces before the '.exe' executable name.
        """
        if not path_name or path_name.startswith('"'):
            return False
        lower = path_name.lower()
        exe_idx = lower.find(".exe")
        if exe_idx == -1:
            return False
        exec_part = path_name[: exe_idx + 4].strip()
        return " " in exec_part

    def _evaluate_checks(
        self,
        services: List[ServiceItemDetail],
        total_count: int,
        running_count: int,
        elevated_running: int,
    ):
        checks = []

        # SVC-001: Unquoted Service Binary Paths (CWE-428)
        unquoted = [s for s in services if s.has_unquoted_path_risk]
        if unquoted:
            detail = "; ".join(f"{s.name} ({s.path_name})" for s in unquoted[:4])
            checks.append(
                self.make_check(
                    check_id="SVC-001",
                    title="Unquoted Service Binary Paths (CWE-428)",
                    description="Check all Windows services for unquoted executable paths containing spaces.",
                    status=CheckStatus.FAIL,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.CONFIRMED_VULNERABILITY,
                    evidence=f"Detected {len(unquoted)} service(s) with unquoted paths containing spaces: {detail}",
                    explanation="When a service path contains spaces and is unquoted, Windows attempts to execute binaries at each space boundary (e.g. C:\\Program.exe), enabling privilege escalation if a parent folder is writable.",
                    remediation="Wrap the ImagePath registry value in double quotes for each affected service in HKLM:\\SYSTEM\\CurrentControlSet\\Services.",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="SVC-001",
                    title="Unquoted Service Binary Paths (CWE-428)",
                    description="Check all Windows services for unquoted executable paths containing spaces.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=f"Inspected {total_count} services; 0 unquoted service binary paths with spaces were found.",
                    explanation="Properly quoting service binary paths prevents search-order hijacking and LocalSystem privilege escalation.",
                    remediation="No action required.",
                )
            )

        # SVC-002: Remote Registry Service Status
        rem_reg = next((s for s in services if s.name.lower() == "remoteregistry"), None)
        if rem_reg and rem_reg.state.lower() == "running":
            checks.append(
                self.make_check(
                    check_id="SVC-002",
                    title="Remote Registry Service Hardening",
                    description="Verify that the Remote Registry service (RemoteRegistry) is stopped and disabled.",
                    status=CheckStatus.FAIL,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"RemoteRegistry is currently {rem_reg.state} (StartMode: {rem_reg.start_mode}).",
                    explanation="An active Remote Registry service allows remote attackers with compromised credentials to extract SAM/SECURITY hive secrets or modify system persistence keys.",
                    remediation="Stop and disable RemoteRegistry via 'Stop-Service RemoteRegistry; Set-Service RemoteRegistry -StartupType Disabled'.",
                )
            )
        else:
            ev = (
                f"RemoteRegistry is {rem_reg.state} (StartMode: {rem_reg.start_mode})."
                if rem_reg
                else "RemoteRegistry service is not active."
            )
            checks.append(
                self.make_check(
                    check_id="SVC-002",
                    title="Remote Registry Service Hardening",
                    description="Verify that the Remote Registry service (RemoteRegistry) is stopped and disabled.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=ev,
                    explanation="Keeping Remote Registry stopped prevents remote registry enumeration and lateral movement.",
                    remediation="No action required.",
                )
            )

        # SVC-003: Insecure Legacy Network Services
        legacy_names = {"tlntsvr", "simptcp", "snmp", "ftpsvc"}
        running_legacy = [
            s for s in services if s.name.lower() in legacy_names and s.state.lower() == "running"
        ]
        if running_legacy:
            names = ", ".join(f"{s.display_name} ({s.name})" for s in running_legacy)
            checks.append(
                self.make_check(
                    check_id="SVC-003",
                    title="Insecure Legacy Network Services (Telnet, FTP, SNMP, Simple TCP)",
                    description="Ensure legacy cleartext or amplification-prone services are not running.",
                    status=CheckStatus.FAIL,
                    severity=SeverityLevel.CRITICAL,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"Running legacy network service(s): {names}",
                    explanation="Services like Telnet and FTP transmit credentials in cleartext and expose the workstation to network exploitation.",
                    remediation="Stop and disable all unnecessary legacy network services.",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="SVC-003",
                    title="Insecure Legacy Network Services (Telnet, FTP, SNMP, Simple TCP)",
                    description="Ensure legacy cleartext or amplification-prone services are not running.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.CRITICAL,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence="Telnet (TlntSvr), FTP (FTPSVC), SNMP, and Simple TCP/IP services are not running.",
                    explanation="Disabling legacy cleartext daemons eliminates network credential sniffing and service exploitation vectors.",
                    remediation="No action required.",
                )
            )

        # SVC-004: Print Spooler Service Exposure
        spooler = next((s for s in services if s.name.lower() == "spooler"), None)
        if spooler and spooler.state.lower() == "running":
            checks.append(
                self.make_check(
                    check_id="SVC-004",
                    title="Print Spooler Service Status",
                    description="Assess whether the Windows Print Spooler service (Spooler) is active and running as LocalSystem.",
                    status=CheckStatus.WARNING,
                    severity=SeverityLevel.LOW,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=f"Print Spooler (Spooler) is Running as '{spooler.start_name}' (StartMode: {spooler.start_mode}).",
                    explanation="Print Spooler runs as LocalSystem by default. While needed for local printing, it has historically been a frequent vector for privilege escalation (e.g., PrintNightmare).",
                    remediation="If printing is not required on this machine, disable the Spooler service or disable 'Allow Print Spooler to accept client connections' in Group Policy.",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="SVC-004",
                    title="Print Spooler Service Status",
                    description="Assess whether the Windows Print Spooler service (Spooler) is active and running as LocalSystem.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.LOW,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence="Print Spooler (Spooler) is Stopped.",
                    explanation="Stopping the Print Spooler when printing is not needed removes a common LocalSystem attack surface.",
                    remediation="No action required.",
                )
            )

        # SVC-005: Third-Party Services Running as LocalSystem
        third_party_system = [
            s for s in services
            if s.state.lower() == "running"
            and s.is_elevated_system
            and s.path_name
            and "c:\\windows" not in s.path_name.lower()
        ]
        if len(third_party_system) > 10:
            names = ", ".join(s.name for s in third_party_system[:6])
            checks.append(
                self.make_check(
                    check_id="SVC-005",
                    title="Third-Party Services Running as LocalSystem",
                    description="Evaluate non-Windows services executing with unrestricted LocalSystem privileges.",
                    status=CheckStatus.WARNING,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"{len(third_party_system)} third-party services are running as LocalSystem (including: {names}). Total LocalSystem running services: {elevated_running}/{running_count}.",
                    explanation="Every third-party service running as LocalSystem represents full OS compromise if a vulnerability exists in that vendor daemon.",
                    remediation="Audit third-party background services and uninstall unused software or downgrade service accounts to LocalService where supported.",
                )
            )
        else:
            names = ", ".join(s.name for s in third_party_system[:6]) or "None"
            checks.append(
                self.make_check(
                    check_id="SVC-005",
                    title="Third-Party Services Running as LocalSystem",
                    description="Evaluate non-Windows services executing with unrestricted LocalSystem privileges.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=f"{len(third_party_system)} third-party services running as LocalSystem ({names}). Total running services: {running_count}.",
                    explanation="A low number of third-party LocalSystem services minimizes privilege escalation risk from third-party background agents.",
                    remediation="Periodically review installed background services.",
                )
            )

        return checks
