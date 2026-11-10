"""Module B: Local Windows User Account & Password Policy Auditor."""
import re
from typing import Dict, List, Optional
from app.auditors.base import BaseAuditor
from app.core.powershell import run_powershell
from app.schemas.audit_schemas import (
    AuditCategory,
    CheckStatus,
    FindingType,
    PasswordPolicySummary,
    SeverityLevel,
    UserAccountDetail,
    UserAuditModuleResult,
)


class UserAccountAuditor(BaseAuditor):
    """Inspects local Windows user accounts, privilege groups, and password policies."""

    category = AuditCategory.USER_ACCOUNTS

    def run_audit(self) -> UserAuditModuleResult:
        ps_script = """
        $users = Get-LocalUser | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Enabled = [bool]$_.Enabled
                PasswordRequired = [bool]$_.PasswordRequired
                PasswordNeverExpires = [bool]$_.PasswordNeverExpires
                UserMayChangePassword = [bool]$_.UserMayChangePassword
                LastLogon = if ($_.LastLogon) { $_.LastLogon.ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
                SID = $_.SID.Value
                Description = $_.Description
                PrincipalSource = $_.PrincipalSource.ToString()
            }
        }
        $admins = @()
        try {
            $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Name
                    SID = if ($_.SID) { $_.SID.Value } else { "" }
                    ObjectClass = $_.ObjectClass
                }
            }
        } catch {
            $adsi = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
            $admins = @($adsi.psbase.Invoke("Members")) | ForEach-Object {
                $n = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
                [PSCustomObject]@{
                    Name = $n
                    SID = ""
                    ObjectClass = "User"
                }
            }
        }
        $netAccounts = (net accounts) -join "`n"
        [PSCustomObject]@{
            Users = @($users)
            Admins = @($admins)
            NetAccounts = $netAccounts
        }
        """
        res = run_powershell(ps_script, timeout=20, expect_json=True)
        payload = res.parsed_json if isinstance(res.parsed_json, dict) else {}

        raw_users = payload.get("Users") or []
        if isinstance(raw_users, dict):
            raw_users = [raw_users]

        raw_admins = payload.get("Admins") or []
        if isinstance(raw_admins, dict):
            raw_admins = [raw_admins]

        net_accounts_text = payload.get("NetAccounts") or ""
        policy = self._parse_net_accounts(net_accounts_text)

        admin_sids = {str(a.get("SID")) for a in raw_admins if a.get("SID")}
        admin_short_names = {
            str(a.get("Name", "")).split("\\")[-1].lower()
            for a in raw_admins
            if a.get("Name")
        }

        accounts: List[UserAccountDetail] = []
        for u in raw_users:
            uname = str(u.get("Name", "Unknown"))
            sid = str(u.get("SID", ""))
            enabled = bool(u.get("Enabled", False))
            pwd_req = bool(u.get("PasswordRequired", True))
            pwd_never_exp = bool(u.get("PasswordNeverExpires", False))
            last_logon = u.get("LastLogon")
            desc = u.get("Description") or ""

            is_admin = (sid in admin_sids) or (uname.lower() in admin_short_names)
            if sid.endswith("-500"):
                acct_type = "Built-in Administrator"
            elif sid.endswith("-501"):
                acct_type = "Built-in Guest"
            elif sid.endswith("-503") or sid.endswith("-504"):
                acct_type = "System Managed Account"
            elif is_admin:
                acct_type = "Local Administrator"
            else:
                acct_type = "Standard User"

            risks: List[str] = []
            recs: List[str] = []
            risk_level = SeverityLevel.INFORMATIONAL

            if sid.endswith("-501") and enabled:
                risks.append("Built-in Guest account is enabled, allowing anonymous or unauthenticated local access.")
                recs.append("Disable the Guest account immediately using 'Disable-LocalUser -Name Guest'.")
                risk_level = SeverityLevel.HIGH

            if sid.endswith("-500") and enabled:
                risks.append("Built-in Administrator account (SID -500) is enabled; it is a well-known target for brute-force attacks.")
                recs.append("Disable the built-in Administrator account and use a dedicated named admin account.")
                if risk_level == SeverityLevel.INFORMATIONAL:
                    risk_level = SeverityLevel.MEDIUM

            if enabled and not pwd_req:
                risks.append("Account is enabled and does NOT require a password (PasswordRequired=False).")
                recs.append("Enforce a strong password requirement for this account immediately.")
                risk_level = SeverityLevel.CRITICAL

            if enabled and pwd_never_exp and not sid.endswith("-503") and not sid.endswith("-504"):
                risks.append("Password is set to never expire (PasswordNeverExpires=True).")
                recs.append("Configure password expiration or enforce strong MFA / passphrase rotation policy.")
                if risk_level in (SeverityLevel.INFORMATIONAL, SeverityLevel.LOW):
                    risk_level = SeverityLevel.MEDIUM

            if enabled and is_admin and not sid.endswith("-500"):
                risks.append("Account possesses persistent local Administrator privileges.")
                recs.append("Use a standard user account for daily tasks and elevate via UAC only when needed.")
                if risk_level == SeverityLevel.INFORMATIONAL:
                    risk_level = SeverityLevel.LOW

            if not risks:
                recs.append("No immediate account-level misconfigurations detected.")

            accounts.append(
                UserAccountDetail(
                    username=uname,
                    enabled=enabled,
                    account_type=acct_type,
                    is_admin=is_admin,
                    password_required=pwd_req,
                    password_never_expires=pwd_never_exp,
                    last_logon=last_logon,
                    sid=sid,
                    description=desc,
                    identified_risks=risks,
                    recommendations=recs,
                    risk_level=risk_level,
                )
            )

        checks = self._evaluate_checks(accounts, policy)
        enabled_count = sum(1 for a in accounts if a.enabled)
        admin_count = sum(1 for a in accounts if a.is_admin and a.enabled)

        return UserAuditModuleResult(
            checks=checks,
            accounts=accounts,
            password_policy=policy,
            total_accounts=len(accounts),
            enabled_accounts=enabled_count,
            admin_accounts=admin_count,
        )

    def _parse_net_accounts(self, text: str) -> PasswordPolicySummary:
        def extract(pattern: str) -> Optional[str]:
            m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            return m.group(1).strip() if m else None

        min_len_str = extract(r"Minimum password length\s*:\s*(\S+)")
        min_age_str = extract(r"Minimum password age \(days\)\s*:\s*(\S+)")
        max_age_str = extract(r"Maximum password age \(days\)\s*:\s*(.+)")
        lockout_str = extract(r"Lockout threshold\s*:\s*(.+)")
        lock_dur_str = extract(r"Lockout duration \(minutes\)\s*:\s*(.+)")
        lock_obs_str = extract(r"Lockout observation window \(minutes\)\s*:\s*(.+)")
        hist_str = extract(r"Length of password history maintained\s*:\s*(.+)")

        return PasswordPolicySummary(
            min_password_length=int(min_len_str) if (min_len_str and min_len_str.isdigit()) else 0,
            min_password_age_days=int(min_age_str) if (min_age_str and min_age_str.isdigit()) else 0,
            max_password_age_days=max_age_str or "Unknown",
            lockout_threshold=lockout_str or "Never",
            lockout_duration_mins=lock_dur_str or "N/A",
            lockout_observation_mins=lock_obs_str or "N/A",
            password_history_length=hist_str or "None",
        )

    def _evaluate_checks(
        self, accounts: List[UserAccountDetail], policy: PasswordPolicySummary
    ):
        checks = []

        # USR-001: Guest Account Status
        guest = next((a for a in accounts if (a.sid and a.sid.endswith("-501")) or a.username.lower() == "guest"), None)
        if guest is None:
            checks.append(
                self.make_check(
                    check_id="USR-001",
                    title="Built-in Guest Account Status",
                    description="Verify that the built-in Windows Guest account is disabled.",
                    status=CheckStatus.NOT_ASSESSED,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence="Guest account was not returned by Get-LocalUser.",
                    explanation="An active Guest account allows unauthenticated users to log in locally or over the network.",
                    remediation="Ensure the Guest account remains disabled via Local Security Policy.",
                )
            )
        elif guest.enabled:
            checks.append(
                self.make_check(
                    check_id="USR-001",
                    title="Built-in Guest Account Status",
                    description="Verify that the built-in Windows Guest account is disabled.",
                    status=CheckStatus.FAIL,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"Account '{guest.username}' (SID: {guest.sid}) has Enabled = True.",
                    explanation="Enabling the Guest account grants unauthenticated users access to the system without individual accountability.",
                    remediation="Run PowerShell as Administrator: Disable-LocalUser -Name 'Guest'",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="USR-001",
                    title="Built-in Guest Account Status",
                    description="Verify that the built-in Windows Guest account is disabled.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=f"Account '{guest.username}' (SID: {guest.sid}) is Disabled (Enabled = False).",
                    explanation="Disabling the Guest account prevents anonymous local and network access.",
                    remediation="No action required. Maintain Guest account in disabled state.",
                )
            )

        # USR-002: Built-in Administrator Account Status
        builtin_admin = next((a for a in accounts if a.sid and a.sid.endswith("-500")), None)
        if builtin_admin and builtin_admin.enabled:
            checks.append(
                self.make_check(
                    check_id="USR-002",
                    title="Built-in Administrator Account (RID 500) Status",
                    description="Check whether the default built-in Administrator account is disabled.",
                    status=CheckStatus.WARNING,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"Built-in Administrator '{builtin_admin.username}' (SID: {builtin_admin.sid}) is Enabled.",
                    explanation="The built-in Administrator account has a well-known SID (-500) and is frequently targeted in credential stuffing and pass-the-hash attacks.",
                    remediation="Disable the built-in Administrator account once a dedicated named admin account is verified.",
                )
            )
        else:
            ev = (
                f"Built-in Administrator '{builtin_admin.username}' (SID: {builtin_admin.sid}) is Disabled."
                if builtin_admin
                else "Built-in RID 500 account not active."
            )
            checks.append(
                self.make_check(
                    check_id="USR-002",
                    title="Built-in Administrator Account (RID 500) Status",
                    description="Check whether the default built-in Administrator account is disabled.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=ev,
                    explanation="Keeping the built-in Administrator account disabled reduces the attack surface for RID-500 brute-force attacks.",
                    remediation="No action required.",
                )
            )

        # USR-003: Administrative Privilege Minimization
        enabled_admins = [a for a in accounts if a.enabled and a.is_admin]
        admin_names = ", ".join(a.username for a in enabled_admins) or "None"
        if len(enabled_admins) > 2:
            checks.append(
                self.make_check(
                    check_id="USR-003",
                    title="Administrative Privilege Minimization",
                    description="Ensure only essential accounts are members of the local Administrators group.",
                    status=CheckStatus.FAIL,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"{len(enabled_admins)} enabled accounts have Administrator privileges: {admin_names}.",
                    explanation="Excessive administrator accounts increase the risk of privilege compromise if any single account is phished or compromised.",
                    remediation="Remove unnecessary users from the local Administrators group using 'Remove-LocalGroupMember -Group Administrators -Member <User>'.",
                )
            )
        elif len(enabled_admins) == 2:
            checks.append(
                self.make_check(
                    check_id="USR-003",
                    title="Administrative Privilege Minimization",
                    description="Ensure only essential accounts are members of the local Administrators group.",
                    status=CheckStatus.WARNING,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=f"2 enabled accounts have Administrator privileges: {admin_names}.",
                    explanation="Following the Principle of Least Privilege, daily user accounts should be Standard Users and only 1 dedicated admin account should exist.",
                    remediation="Review whether all listed administrator accounts require persistent administrative rights.",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="USR-003",
                    title="Administrative Privilege Minimization",
                    description="Ensure only essential accounts are members of the local Administrators group.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=f"{len(enabled_admins)} enabled Administrator account(s) detected: {admin_names}.",
                    explanation="Restricting administrative privileges to a single administrative identity adheres to the Principle of Least Privilege.",
                    remediation="Continue using Standard User accounts for routine non-administrative tasks.",
                )
            )

        # USR-004: Accounts Without Password Requirement
        no_pwd_enabled = [a for a in accounts if a.enabled and not a.password_required]
        if no_pwd_enabled:
            names = ", ".join(a.username for a in no_pwd_enabled)
            checks.append(
                self.make_check(
                    check_id="USR-004",
                    title="Password Requirement on Enabled Accounts",
                    description="Check if any enabled local user accounts do not require a password.",
                    status=CheckStatus.FAIL,
                    severity=SeverityLevel.CRITICAL,
                    finding_type=FindingType.CONFIRMED_VULNERABILITY,
                    evidence=f"Enabled account(s) with PasswordRequired=False: {names}",
                    explanation="Accounts that do not require a password allow trivial unauthorized local login and privilege escalation.",
                    remediation="Set a strong password and enforce PasswordRequired on all enabled local user accounts.",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="USR-004",
                    title="Password Requirement on Enabled Accounts",
                    description="Check if any enabled local user accounts do not require a password.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.CRITICAL,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=f"All { sum(1 for a in accounts if a.enabled) } enabled local account(s) have PasswordRequired = True.",
                    explanation="Requiring passwords on all enabled user accounts prevents unauthenticated interactive logins.",
                    remediation="No action required.",
                )
            )

        # USR-005: Non-Expiring Passwords on Active Accounts
        never_exp_users = [
            a for a in accounts
            if a.enabled and a.password_never_expires and not (a.sid and (a.sid.endswith("-503") or a.sid.endswith("-504")))
        ]
        if never_exp_users:
            names = ", ".join(a.username for a in never_exp_users)
            checks.append(
                self.make_check(
                    check_id="USR-005",
                    title="Password Expiration Policy on Active Accounts",
                    description="Check whether active local user accounts have non-expiring passwords.",
                    status=CheckStatus.WARNING,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"Enabled account(s) with PasswordNeverExpires = True: {names}",
                    explanation="When passwords never expire and lack MFA, compromised credentials remain valid indefinitely.",
                    remediation="Enable password expiration via 'Set-LocalUser -Name <User> -PasswordNeverExpires $false' or enforce Windows Hello MFA.",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="USR-005",
                    title="Password Expiration Policy on Active Accounts",
                    description="Check whether active local user accounts have non-expiring passwords.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence="All enabled user accounts enforce password expiration.",
                    explanation="Periodic credential rotation limits the window of exposure for leaked credentials.",
                    remediation="No action required.",
                )
            )

        # USR-006: Minimum Password Length Policy
        min_len = policy.min_password_length or 0
        if min_len == 0:
            checks.append(
                self.make_check(
                    check_id="USR-006",
                    title="System Minimum Password Length Policy",
                    description="Verify that Windows Local Security Policy enforces a minimum password length (>= 8 chars).",
                    status=CheckStatus.FAIL,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"net accounts reports Minimum password length: {min_len} characters.",
                    explanation="A minimum password length of 0 permits blank or short passwords that can be cracked instantaneously.",
                    remediation="Configure Minimum Password Length to at least 12 characters via secpol.msc or 'net accounts /minpwlen:12' (as Administrator).",
                )
            )
        elif min_len < 8:
            checks.append(
                self.make_check(
                    check_id="USR-006",
                    title="System Minimum Password Length Policy",
                    description="Verify that Windows Local Security Policy enforces a minimum password length (>= 8 chars).",
                    status=CheckStatus.WARNING,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"net accounts reports Minimum password length: {min_len} characters.",
                    explanation="Passwords shorter than 8 characters are vulnerable to modern GPU hash-cracking attacks.",
                    remediation="Increase Minimum Password Length to 12 or more characters via Local Security Policy (secpol.msc).",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="USR-006",
                    title="System Minimum Password Length Policy",
                    description="Verify that Windows Local Security Policy enforces a minimum password length (>= 8 chars).",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=f"net accounts reports Minimum password length: {min_len} characters.",
                    explanation="Enforcing a strong minimum password length protects local NTLM hashes against offline brute-force attacks.",
                    remediation="Maintain minimum password length at 12+ characters.",
                )
            )

        # USR-007: Account Lockout Threshold Policy
        lockout = (policy.lockout_threshold or "Never").strip()
        if lockout.lower() == "never" or lockout == "0":
            checks.append(
                self.make_check(
                    check_id="USR-007",
                    title="Account Lockout Threshold Policy",
                    description="Verify that an account lockout threshold is configured to mitigate brute-force login attempts.",
                    status=CheckStatus.WARNING,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"net accounts reports Lockout threshold: {lockout}.",
                    explanation="Without an account lockout threshold, attackers can attempt unlimited password guesses against local accounts.",
                    remediation="Set Account Lockout Threshold to 5–10 invalid logon attempts via 'net accounts /lockoutthreshold:5' (as Administrator).",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="USR-007",
                    title="Account Lockout Threshold Policy",
                    description="Verify that an account lockout threshold is configured to mitigate brute-force login attempts.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=f"net accounts reports Lockout threshold: {lockout} invalid attempts (Duration: {policy.lockout_duration_mins} mins).",
                    explanation="An active account lockout policy automatically throttles automated password-spraying and brute-force attacks.",
                    remediation="No action required.",
                )
            )

        return checks
