"""Module D: Windows File and Directory NTFS Permission Auditor."""
from typing import List
from app.auditors.base import BaseAuditor
from app.core.powershell import run_powershell
from app.schemas.audit_schemas import (
    AuditCategory,
    CheckStatus,
    FindingType,
    PermissionAuditModuleResult,
    PermissionEntryItem,
    SeverityLevel,
)


class FilePermissionAuditor(BaseAuditor):
    """Inspects NTFS ACLs on critical system directories, startup paths, and configuration files."""

    category = AuditCategory.FILE_PERMISSIONS

    def run_audit(self) -> PermissionAuditModuleResult:
        ps_script = """
        $targets = @(
            @{ Path = "C:\\Windows\\System32"; CriticalSystem = $true; Label = "Windows System32 Binaries" },
            @{ Path = "C:\\Windows\\System32\\drivers\\etc\\hosts"; CriticalSystem = $true; Label = "System Hosts File" },
            @{ Path = "C:\\Program Files"; CriticalSystem = $true; Label = "Program Files Directory" },
            @{ Path = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"; CriticalSystem = $true; Label = "All Users Startup Folder" },
            @{ Path = "C:\\Users\\Public"; CriticalSystem = $false; Label = "Public Shared User Directory" },
            @{ Path = "C:\\Windows\\Temp"; CriticalSystem = $false; Label = "System Temp Directory" }
        )

        $results = @()
        foreach ($t in $targets) {
            $p = $t.Path
            if (-not (Test-Path -LiteralPath $p)) {
                $results += [PSCustomObject]@{
                    Path = $p
                    Label = $t.Label
                    CriticalSystem = $t.CriticalSystem
                    Exists = $false
                    Accessible = $false
                    Owner = "N/A"
                    Access = @()
                }
                continue
            }
            try {
                $acl = Get-Acl -LiteralPath $p -ErrorAction Stop
                $aces = @($acl.Access) | ForEach-Object {
                    [PSCustomObject]@{
                        IdentityReference = $_.IdentityReference.Value
                        FileSystemRights = $_.FileSystemRights.ToString()
                        AccessControlType = $_.AccessControlType.ToString()
                        IsInherited = [bool]$_.IsInherited
                    }
                }
                $results += [PSCustomObject]@{
                    Path = $p
                    Label = $t.Label
                    CriticalSystem = $t.CriticalSystem
                    Exists = $true
                    Accessible = $true
                    Owner = [string]$acl.Owner
                    Access = @($aces)
                }
            } catch {
                $results += [PSCustomObject]@{
                    Path = $p
                    Label = $t.Label
                    CriticalSystem = $t.CriticalSystem
                    Exists = $true
                    Accessible = $false
                    Owner = "Access Denied"
                    Access = @()
                }
            }
        }
        $results
        """
        res = run_powershell(ps_script, timeout=25, expect_json=True)
        raw_targets = res.parsed_json if isinstance(res.parsed_json, list) else (
            [res.parsed_json] if isinstance(res.parsed_json, dict) else []
        )

        entries: List[PermissionEntryItem] = []
        broad_principals = (
            "everyone",
            "builtin\\users",
            "nt authority\\authenticated users",
            "nt authority\\anonymous logon",
            "builtin\\guests",
        )
        write_keywords = (
            "fullcontrol",
            "modify",
            "write",
            "writedata",
            "createfiles",
            "appenddata",
            "changepermissions",
            "takeownership",
        )

        for tgt in raw_targets:
            path = str(tgt.get("Path") or "")
            critical_sys = bool(tgt.get("CriticalSystem", True))
            exists = bool(tgt.get("Exists", False))
            accessible = bool(tgt.get("Accessible", False))
            owner = str(tgt.get("Owner") or "Unknown")
            aces = tgt.get("Access") or []
            if isinstance(aces, dict):
                aces = [aces]

            if not exists or not accessible:
                entries.append(
                    PermissionEntryItem(
                        path=path,
                        exists=exists,
                        accessible=accessible,
                        owner=owner,
                        identity="N/A",
                        rights="Unavailable",
                        access_control_type="N/A",
                        is_inherited=False,
                        is_risky=False,
                        security_concern="Path did not exist or ACL could not be read under current user context.",
                        recommended_action="Run WinSecAudit as Administrator to inspect restricted ACLs.",
                        severity=SeverityLevel.INFORMATIONAL,
                    )
                )
                continue

            for ace in aces:
                identity = str(ace.get("IdentityReference") or "")
                rights = str(ace.get("FileSystemRights") or "")
                ac_type = str(ace.get("AccessControlType") or "Allow")
                is_inherited = bool(ace.get("IsInherited", False))

                id_lower = identity.lower()
                rights_lower = rights.lower()

                is_broad = any(bp in id_lower for bp in broad_principals)
                has_write = any(wk in rights_lower for wk in write_keywords) and ac_type.lower() == "allow"
                has_full = "fullcontrol" in rights_lower and ac_type.lower() == "allow"

                is_risky = False
                concern = "Standard NTFS Access Control Entry."
                rec_action = "No change required."
                sev = SeverityLevel.INFORMATIONAL

                if "everyone" in id_lower and has_full:
                    is_risky = True
                    sev = SeverityLevel.CRITICAL
                    concern = f"'Everyone' group holds FullControl on '{path}', allowing any local or network user to overwrite or delete files."
                    rec_action = f"Remove 'Everyone' FullControl ACE on '{path}' using icacls and restrict access to Administrators and SYSTEM."
                elif "everyone" in id_lower and has_write:
                    is_risky = True
                    sev = SeverityLevel.HIGH
                    concern = f"'Everyone' group holds write/modify permissions ({rights}) on '{path}'."
                    rec_action = f"Restrict 'Everyone' to ReadAndExecute or remove the ACE on '{path}'."
                elif critical_sys and is_broad and has_write:
                    is_risky = True
                    sev = SeverityLevel.HIGH if not is_inherited else SeverityLevel.MEDIUM
                    concern = (
                        f"Non-administrative principal '{identity}' has write/modify capability ({rights}) on sensitive system path '{path}'. "
                        "This can enable binary planting, startup persistence, or DNS hijacking."
                    )
                    rec_action = f"Revoke write/modify permissions for '{identity}' on '{path}'; allow only ReadAndExecute for standard users."
                elif not critical_sys and is_broad and has_full:
                    is_risky = True
                    sev = SeverityLevel.MEDIUM
                    concern = f"Broad principal '{identity}' has FullControl ({rights}) on shared path '{path}'."
                    rec_action = "Ensure standard users do not have ChangePermissions or TakeOwnership rights on shared directories."

                entries.append(
                    PermissionEntryItem(
                        path=path,
                        exists=exists,
                        accessible=accessible,
                        owner=owner,
                        identity=identity,
                        rights=rights,
                        access_control_type=ac_type,
                        is_inherited=is_inherited,
                        is_risky=is_risky,
                        security_concern=concern,
                        recommended_action=rec_action,
                        severity=sev,
                    )
                )

        checks = self._evaluate_checks(raw_targets, entries)
        risky_count = sum(1 for e in entries if e.is_risky)

        return PermissionAuditModuleResult(
            checks=checks,
            inspected_paths_count=len(raw_targets),
            risky_permissions_count=risky_count,
            entries=entries,
        )

    def _evaluate_checks(self, raw_targets: list, entries: List[PermissionEntryItem]):
        checks = []

        # PERM-001: Unnecessary Everyone FullControl / Write Permissions
        everyone_risks = [
            e for e in entries
            if "everyone" in e.identity.lower() and e.is_risky
        ]
        if everyone_risks:
            detail = "; ".join(f"{e.path} ({e.identity}: {e.rights})" for e in everyone_risks[:4])
            checks.append(
                self.make_check(
                    check_id="PERM-001",
                    title="Overly Broad 'Everyone' Write/FullControl Permissions",
                    description="Check whether the 'Everyone' security principal is granted write, modify, or full control on audited paths.",
                    status=CheckStatus.FAIL,
                    severity=SeverityLevel.CRITICAL,
                    finding_type=FindingType.CONFIRMED_VULNERABILITY,
                    evidence=f"Detected {len(everyone_risks)} risky 'Everyone' ACE(s): {detail}",
                    explanation="Granting 'Everyone' write or FullControl access allows any user or compromised process to tamper with critical files.",
                    remediation="Remove 'Everyone' write/FullControl permissions using 'icacls <path> /remove Everyone' or limit to Read-Only.",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="PERM-001",
                    title="Overly Broad 'Everyone' Write/FullControl Permissions",
                    description="Check whether the 'Everyone' security principal is granted write, modify, or full control on audited paths.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.CRITICAL,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence="0 audited directories or files grant Write, Modify, or FullControl to 'Everyone'.",
                    explanation="Preventing 'Everyone' write access protects system integrity against unauthorized tampering.",
                    remediation="No action required.",
                )
            )

        # PERM-002: System32 and Program Files Integrity Permissions
        sys_paths = {"c:\\windows\\system32", "c:\\program files"}
        sys_risks = [
            e for e in entries
            if e.path.lower() in sys_paths and e.is_risky
        ]
        if sys_risks:
            detail = "; ".join(f"{e.path} -> {e.identity} ({e.rights})" for e in sys_risks[:4])
            checks.append(
                self.make_check(
                    check_id="PERM-002",
                    title="System32 and Program Files Write Protection",
                    description="Verify that standard users cannot modify binaries inside C:\\Windows\\System32 or C:\\Program Files.",
                    status=CheckStatus.FAIL,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.CONFIRMED_VULNERABILITY,
                    evidence=f"Writable system directory ACE(s) detected: {detail}",
                    explanation="Write access to System32 or Program Files enables DLL hijacking and privilege escalation to SYSTEM.",
                    remediation="Restore default Windows ACLs so only TrustedInstaller, SYSTEM, and Administrators have write permissions.",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="PERM-002",
                    title="System32 and Program Files Write Protection",
                    description="Verify that standard users cannot modify binaries inside C:\\Windows\\System32 or C:\\Program Files.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence="C:\\Windows\\System32 and C:\\Program Files restrict write/modify access to TrustedInstaller, SYSTEM, and Administrators.",
                    explanation="Strict ACLs on OS and application binary directories prevent local privilege escalation via binary replacement.",
                    remediation="No action required.",
                )
            )

        # PERM-003: System Startup Directory ACL Protection
        startup_path = "c:\\programdata\\microsoft\\windows\\start menu\\programs\\startup"
        startup_risks = [
            e for e in entries
            if e.path.lower() == startup_path and e.is_risky
        ]
        if startup_risks:
            detail = "; ".join(f"{e.identity} ({e.rights})" for e in startup_risks)
            checks.append(
                self.make_check(
                    check_id="PERM-003",
                    title="All-Users Startup Directory Permission Hardening",
                    description="Verify that non-administrators cannot drop executables into the machine-wide Startup folder.",
                    status=CheckStatus.FAIL,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.CONFIRMED_VULNERABILITY,
                    evidence=f"All-Users Startup folder grants write access to: {detail}",
                    explanation="If standard users can write to the ProgramData Startup folder, they can plant malicious payloads that execute when an Administrator logs in.",
                    remediation="Restrict write permissions on C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp to Administrators and SYSTEM.",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="PERM-003",
                    title="All-Users Startup Directory Permission Hardening",
                    description="Verify that non-administrators cannot drop executables into the machine-wide Startup folder.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence="Machine-wide Startup folder prevents write/modify operations by standard users.",
                    explanation="Securing the global Startup folder prevents cross-account persistence and privilege escalation.",
                    remediation="No action required.",
                )
            )

        # PERM-004: System Hosts File Integrity Protection
        hosts_path = "c:\\windows\\system32\\drivers\\etc\\hosts"
        hosts_risks = [
            e for e in entries
            if e.path.lower() == hosts_path and e.is_risky
        ]
        if hosts_risks:
            detail = "; ".join(f"{e.identity} ({e.rights})" for e in hosts_risks)
            checks.append(
                self.make_check(
                    check_id="PERM-004",
                    title="Windows DNS Hosts File ACL Protection",
                    description="Ensure standard non-administrative users cannot modify C:\\Windows\\System32\\drivers\\etc\\hosts.",
                    status=CheckStatus.FAIL,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"Hosts file allows write access by: {detail}",
                    explanation="Unauthorized modification of the hosts file allows malware to redirect domains to phishing or command-and-control servers.",
                    remediation="Remove write permissions for standard users on C:\\Windows\\System32\\drivers\\etc\\hosts.",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="PERM-004",
                    title="Windows DNS Hosts File ACL Protection",
                    description="Ensure standard non-administrative users cannot modify C:\\Windows\\System32\\drivers\\etc\\hosts.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence="C:\\Windows\\System32\\drivers\\etc\\hosts is read-only for standard users and writable only by Administrators/SYSTEM.",
                    explanation="Protecting the hosts file prevents local DNS poisoning and security update redirection.",
                    remediation="No action required.",
                )
            )

        # PERM-005: Shared & Public Directories Exposure Review
        shared_risks = [
            e for e in entries
            if e.path.lower() in ("c:\\users\\public", "c:\\windows\\temp") and e.is_risky
        ]
        if shared_risks:
            detail = "; ".join(f"{e.path} -> {e.identity} ({e.rights})" for e in shared_risks[:3])
            checks.append(
                self.make_check(
                    check_id="PERM-005",
                    title="Shared & Temporary Directory ACL Review",
                    description="Inspect C:\\Users\\Public and C:\\Windows\\Temp for excessive FullControl permissions granted to non-admin groups.",
                    status=CheckStatus.WARNING,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"Broad FullControl permissions detected: {detail}",
                    explanation="While shared folders require creator write access, granting broad FullControl allows users to alter ACLs or delete other users' files.",
                    remediation="Use Creator Owner permissions rather than broad FullControl on shared directories.",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="PERM-005",
                    title="Shared & Temporary Directory ACL Review",
                    description="Inspect C:\\Users\\Public and C:\\Windows\\Temp for excessive FullControl permissions granted to non-admin groups.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence="C:\\Users\\Public and C:\\Windows\\Temp follow standard scoped NTFS inheritance without broad FullControl exposure.",
                    explanation="Properly scoped permissions on shared directories prevent cross-user file tampering.",
                    remediation="No action required.",
                )
            )

        return checks
