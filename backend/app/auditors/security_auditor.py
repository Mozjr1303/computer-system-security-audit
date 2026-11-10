"""Module F: Windows Security Configuration Auditor (Defender, Firewall, UAC, BitLocker, Secure Boot, RDP)."""
from typing import List
from app.auditors.base import BaseAuditor
from app.core.powershell import is_running_as_admin, run_powershell
from app.schemas.audit_schemas import (
    AuditCategory,
    CheckStatus,
    FindingType,
    SecurityConfigModuleResult,
    SecurityControlItem,
    SeverityLevel,
)


class SecurityConfigAuditor(BaseAuditor):
    """Inspects Windows Defender, Firewall profiles, UAC, Secure Boot, BitLocker, RDP, and SMBv1."""

    category = AuditCategory.SECURITY_CONFIG

    def run_audit(self) -> SecurityConfigModuleResult:
        ps_script = """
        $mp = $null
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, AntispywareEnabled, IsTamperProtected, AntivirusSignatureAge, AntivirusSignatureVersion, NISSignatureAge
        } catch {
            $mp = $null
        }

        $fw = @()
        try {
            $fw = Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    Name = [string]$_.Name
                    Enabled = [bool]$_.Enabled
                    DefaultInboundAction = [string]$_.DefaultInboundAction
                    DefaultOutboundAction = [string]$_.DefaultOutboundAction
                }
            }
        } catch {
            $fw = @()
        }

        # UAC Registry settings
        $uacPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        $uac = Get-ItemProperty -Path $uacPath -ErrorAction SilentlyContinue
        $enableLUA = if ($null -ne $uac.EnableLUA) { [int]$uac.EnableLUA } else { $null }
        $consentAdmin = if ($null -ne $uac.ConsentPromptBehaviorAdmin) { [int]$uac.ConsentPromptBehaviorAdmin } else { $null }
        $secureDesktop = if ($null -ne $uac.PromptOnSecureDesktop) { [int]$uac.PromptOnSecureDesktop } else { $null }

        # Remote Desktop settings
        $rdpPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
        $rdp = Get-ItemProperty -Path $rdpPath -ErrorAction SilentlyContinue
        $fDenyTS = if ($null -ne $rdp.fDenyTSConnections) { [int]$rdp.fDenyTSConnections } else { $null }

        $rdpTcpPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
        $rdpTcp = Get-ItemProperty -Path $rdpTcpPath -ErrorAction SilentlyContinue
        $nla = if ($null -ne $rdpTcp.UserAuthentication) { [int]$rdpTcp.UserAuthentication } else { $null }

        # Secure Boot via Registry (accessible without elevation!)
        $sbPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State"
        $sbProp = Get-ItemProperty -Path $sbPath -ErrorAction SilentlyContinue
        $secureBootReg = if ($null -ne $sbProp.UEFISecureBootEnabled) { [int]$sbProp.UEFISecureBootEnabled } else { $null }

        # BitLocker check
        $bitlockerStatus = "NOT_ASSESSED"
        $bitlockerDetail = "Requires Administrator privileges to query Get-BitLockerVolume or WMI EncryptableVolume."
        try {
            $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
            $bitlockerStatus = [string]$bl.ProtectionStatus
            $bitlockerDetail = "Volume C: VolumeStatus=$($bl.VolumeStatus), ProtectionStatus=$($bl.ProtectionStatus), EncryptionPercentage=$($bl.EncryptionPercentage)%"
        } catch {
            if ($_.Exception.Message -match "Access is denied|Administrator|privilege") {
                $bitlockerStatus = "ACCESS_DENIED"
            } else {
                $bitlockerStatus = "UNAVAILABLE"
                $bitlockerDetail = $_.Exception.Message
            }
        }

        # SMBv1 Check via Registry
        $smbPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
        $smbProp = Get-ItemProperty -Path $smbPath -ErrorAction SilentlyContinue
        $smb1 = if ($null -ne $smbProp.SMB1) { [int]$smbProp.SMB1 } else { 0 }
        $smb1Feature = Get-Service -Name mrxsmb10 -ErrorAction SilentlyContinue
        $smb1ServiceState = if ($smb1Feature) { [string]$smb1Feature.Status } else { "NotInstalled" }

        [PSCustomObject]@{
            Defender = $mp
            Firewall = @($fw)
            EnableLUA = $enableLUA
            ConsentPromptBehaviorAdmin = $consentAdmin
            PromptOnSecureDesktop = $secureDesktop
            fDenyTSConnections = $fDenyTS
            RDP_NLA = $nla
            SecureBootEnabled = $secureBootReg
            BitLockerStatus = $bitlockerStatus
            BitLockerDetail = $bitlockerDetail
            SMB1Registry = $smb1
            SMB1DriverState = $smb1ServiceState
        }
        """
        res = run_powershell(ps_script, timeout=25, expect_json=True)
        payload = res.parsed_json if isinstance(res.parsed_json, dict) else {}

        controls: List[SecurityControlItem] = []
        checks = []

        # 1. SEC-001: Windows Defender Real-Time Protection
        mp = payload.get("Defender")
        if not isinstance(mp, dict):
            c_status = CheckStatus.NOT_ASSESSED
            c_sev = SeverityLevel.CRITICAL
            ev = "Get-MpComputerStatus returned null or could not be queried."
            state_lbl = "Not Assessed"
        else:
            av_enabled = bool(mp.get("AntivirusEnabled", False))
            rtp_enabled = bool(mp.get("RealTimeProtectionEnabled", False))
            bm_enabled = bool(mp.get("BehaviorMonitorEnabled", False))
            ev = (
                f"AntivirusEnabled={av_enabled}, RealTimeProtectionEnabled={rtp_enabled}, "
                f"BehaviorMonitorEnabled={bm_enabled}, IoavProtectionEnabled={mp.get('IoavProtectionEnabled')}"
            )
            if av_enabled and rtp_enabled:
                c_status = CheckStatus.PASS
                c_sev = SeverityLevel.CRITICAL
                state_lbl = "Enabled & Active"
            elif av_enabled and not rtp_enabled:
                c_status = CheckStatus.FAIL
                c_sev = SeverityLevel.CRITICAL
                state_lbl = "Real-Time Protection Disabled"
            else:
                c_status = CheckStatus.FAIL
                c_sev = SeverityLevel.CRITICAL
                state_lbl = "Antivirus Disabled"

        checks.append(
            self.make_check(
                check_id="SEC-001",
                title="Windows Defender Antivirus & Real-Time Protection",
                description="Verify that Windows Defender Antivirus and Real-Time Malware Protection are active.",
                status=c_status,
                severity=c_sev,
                finding_type=(
                    FindingType.SECURITY_WEAKNESS
                    if c_status == CheckStatus.FAIL
                    else FindingType.CONFIGURATION_OBSERVATION
                ),
                evidence=ev,
                explanation="Real-Time Protection scans files and process memory on access to block malware execution before infection occurs.",
                remediation="Enable Real-time protection in Windows Security > Virus & threat protection > Manage settings.",
            )
        )
        controls.append(
            SecurityControlItem(
                control_id="SEC-001",
                domain="Endpoint Protection",
                name="Defender Real-Time Protection",
                state_label=state_lbl,
                status=c_status,
                severity=c_sev,
                evidence=ev,
                explanation="Intercepts malware execution in real time.",
                recommendation="Keep Real-Time Protection and Behavior Monitoring enabled at all times.",
            )
        )

        # 2. SEC-002: Windows Defender Security Intelligence (Signature Age)
        if not isinstance(mp, dict) or mp.get("AntivirusSignatureAge") is None:
            sig_status = CheckStatus.NOT_ASSESSED
            sig_ev = "Defender signature age unavailable."
            sig_lbl = "Not Assessed"
        else:
            sig_age = int(mp.get("AntivirusSignatureAge", 0))
            sig_ver = str(mp.get("AntivirusSignatureVersion") or "Unknown")
            sig_ev = f"Signature Version: {sig_ver}, AntivirusSignatureAge: {sig_age} day(s)."
            if sig_age <= 3:
                sig_status = CheckStatus.PASS
                sig_lbl = f"Up to Date ({sig_age}d old)"
            elif sig_age <= 7:
                sig_status = CheckStatus.WARNING
                sig_lbl = f"Slightly Stale ({sig_age}d old)"
            else:
                sig_status = CheckStatus.FAIL
                sig_lbl = f"Outdated ({sig_age}d old)"

        checks.append(
            self.make_check(
                check_id="SEC-002",
                title="Windows Defender Security Intelligence Currency",
                description="Verify that malware definitions (Security Intelligence) have been updated within the last 3 days.",
                status=sig_status,
                severity=SeverityLevel.HIGH,
                finding_type=(
                    FindingType.SECURITY_WEAKNESS
                    if sig_status in (CheckStatus.FAIL, CheckStatus.WARNING)
                    else FindingType.CONFIGURATION_OBSERVATION
                ),
                evidence=sig_ev,
                explanation="Outdated antivirus signatures reduce detection accuracy against newly emerging ransomware and trojans.",
                remediation="Run 'Update-MpSignature' in PowerShell or check for protection updates in Windows Security.",
            )
        )
        controls.append(
            SecurityControlItem(
                control_id="SEC-002",
                domain="Endpoint Protection",
                name="Security Intelligence Signatures",
                state_label=sig_lbl,
                status=sig_status,
                severity=SeverityLevel.HIGH,
                evidence=sig_ev,
                explanation="Provides threat definitions for known malware families.",
                recommendation="Update signatures automatically every 24 hours.",
            )
        )

        # 3. SEC-003: Windows Defender Tamper Protection
        if not isinstance(mp, dict) or mp.get("IsTamperProtected") is None:
            tp_status = CheckStatus.NOT_ASSESSED
            tp_ev = "Tamper protection status unavailable."
            tp_lbl = "Not Assessed"
        else:
            is_tp = bool(mp.get("IsTamperProtected", False))
            tp_ev = f"IsTamperProtected = {is_tp}"
            if is_tp:
                tp_status = CheckStatus.PASS
                tp_lbl = "Enabled"
            else:
                tp_status = CheckStatus.WARNING
                tp_lbl = "Disabled"

        checks.append(
            self.make_check(
                check_id="SEC-003",
                title="Windows Defender Tamper Protection",
                description="Verify that Tamper Protection is enabled to prevent unauthorized modification of Defender settings.",
                status=tp_status,
                severity=SeverityLevel.MEDIUM,
                finding_type=(
                    FindingType.SECURITY_WEAKNESS
                    if tp_status == CheckStatus.WARNING
                    else FindingType.CONFIGURATION_OBSERVATION
                ),
                evidence=tp_ev,
                explanation="Tamper Protection prevents malware or scripts from disabling Windows Defender via registry or PowerShell.",
                remediation="Enable Tamper Protection in Windows Security > Virus & threat protection > Manage settings.",
            )
        )
        controls.append(
            SecurityControlItem(
                control_id="SEC-003",
                domain="Endpoint Protection",
                name="Defender Tamper Protection",
                state_label=tp_lbl,
                status=tp_status,
                severity=SeverityLevel.MEDIUM,
                evidence=tp_ev,
                explanation="Blocks unauthorized disabling of antivirus controls.",
                recommendation="Enable Tamper Protection in Windows Security.",
            )
        )

        # 4. SEC-004: Windows Firewall Profiles (Domain, Private, Public)
        raw_fw = payload.get("Firewall") or []
        if isinstance(raw_fw, dict):
            raw_fw = [raw_fw]

        if not raw_fw:
            fw_status = CheckStatus.NOT_ASSESSED
            fw_ev = "Get-NetFirewallProfile returned no profile data."
            fw_lbl = "Not Assessed"
        else:
            disabled_profiles = [p.get("Name") for p in raw_fw if not p.get("Enabled")]
            fw_ev = ", ".join(
                f"{p.get('Name')}: Enabled={p.get('Enabled')} (In:{p.get('DefaultInboundAction')})"
                for p in raw_fw
            )
            if disabled_profiles:
                fw_status = CheckStatus.FAIL
                fw_lbl = f"Disabled on {', '.join(disabled_profiles)}"
            else:
                fw_status = CheckStatus.PASS
                fw_lbl = "All 3 Profiles Enabled"

        checks.append(
            self.make_check(
                check_id="SEC-004",
                title="Windows Defender Firewall Profile Status (Domain, Private, Public)",
                description="Verify that the host firewall is enabled across Domain, Private, and Public network profiles.",
                status=fw_status,
                severity=SeverityLevel.CRITICAL,
                finding_type=(
                    FindingType.SECURITY_WEAKNESS
                    if fw_status == CheckStatus.FAIL
                    else FindingType.CONFIGURATION_OBSERVATION
                ),
                evidence=fw_ev,
                explanation="The host firewall blocks unsolicited inbound network connections and lateral movement attempts.",
                remediation="Enable all firewall profiles via 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True' (as Administrator).",
            )
        )
        controls.append(
            SecurityControlItem(
                control_id="SEC-004",
                domain="Network Security",
                name="Windows Firewall (All Profiles)",
                state_label=fw_lbl,
                status=fw_status,
                severity=SeverityLevel.CRITICAL,
                evidence=fw_ev,
                explanation="Filters inbound and outbound network traffic across network profiles.",
                recommendation="Keep Domain, Private, and Public firewall profiles enabled with Block Inbound default.",
            )
        )

        # 5. SEC-005: User Account Control (UAC) Configuration
        enable_lua = payload.get("EnableLUA")
        consent_admin = payload.get("ConsentPromptBehaviorAdmin")
        secure_desktop = payload.get("PromptOnSecureDesktop")

        if enable_lua is None:
            uac_status = CheckStatus.NOT_ASSESSED
            uac_ev = "UAC registry keys could not be read."
            uac_lbl = "Not Assessed"
        elif enable_lua == 0:
            uac_status = CheckStatus.FAIL
            uac_ev = f"EnableLUA={enable_lua} (UAC is completely disabled)."
            uac_lbl = "Disabled"
        elif consent_admin == 0:
            uac_status = CheckStatus.FAIL
            uac_ev = f"EnableLUA={enable_lua}, ConsentPromptBehaviorAdmin=0 (Elevate without prompting)."
            uac_lbl = "Silent Elevation (Insecure)"
        elif secure_desktop == 0:
            uac_status = CheckStatus.WARNING
            uac_ev = f"EnableLUA={enable_lua}, ConsentPromptBehaviorAdmin={consent_admin}, PromptOnSecureDesktop=0."
            uac_lbl = "Enabled (No Secure Desktop)"
        else:
            uac_status = CheckStatus.PASS
            uac_ev = f"EnableLUA={enable_lua}, ConsentPromptBehaviorAdmin={consent_admin}, PromptOnSecureDesktop={secure_desktop}."
            uac_lbl = "Enabled (Secure Desktop)"

        checks.append(
            self.make_check(
                check_id="SEC-005",
                title="User Account Control (UAC) & Secure Desktop Configuration",
                description="Verify that UAC is enabled and prompts administrators on the Secure Desktop before privilege elevation.",
                status=uac_status,
                severity=SeverityLevel.HIGH,
                finding_type=(
                    FindingType.SECURITY_WEAKNESS
                    if uac_status in (CheckStatus.FAIL, CheckStatus.WARNING)
                    else FindingType.CONFIGURATION_OBSERVATION
                ),
                evidence=uac_ev,
                explanation="UAC prevents silent privilege escalation by requiring interactive user consent on an isolated Secure Desktop.",
                remediation="Set UAC to 'Notify me only when apps try to make changes to my computer (default)' or higher in User Account Control Settings.",
            )
        )
        controls.append(
            SecurityControlItem(
                control_id="SEC-005",
                domain="Privilege Control",
                name="User Account Control (UAC)",
                state_label=uac_lbl,
                status=uac_status,
                severity=SeverityLevel.HIGH,
                evidence=uac_ev,
                explanation="Isolates administrative token elevation behind an interactive prompt.",
                recommendation="Keep EnableLUA=1 and PromptOnSecureDesktop=1.",
            )
        )

        # 6. SEC-006: Remote Desktop Protocol (RDP) & NLA Configuration
        f_deny_ts = payload.get("fDenyTSConnections")
        rdp_nla = payload.get("RDP_NLA")
        if f_deny_ts is None:
            rdp_status = CheckStatus.NOT_ASSESSED
            rdp_ev = "Terminal Server registry configuration could not be read."
            rdp_lbl = "Not Assessed"
        elif f_deny_ts == 1:
            rdp_status = CheckStatus.PASS
            rdp_ev = "fDenyTSConnections = 1 (Remote Desktop connections are disabled)."
            rdp_lbl = "Disabled (Hardened)"
        elif rdp_nla == 1:
            rdp_status = CheckStatus.WARNING
            rdp_ev = "fDenyTSConnections = 0 (RDP Enabled), UserAuthentication (NLA) = 1."
            rdp_lbl = "Enabled (with NLA)"
        else:
            rdp_status = CheckStatus.FAIL
            rdp_ev = f"fDenyTSConnections = 0 (RDP Enabled) and UserAuthentication (NLA) = {rdp_nla} (NLA Disabled)."
            rdp_lbl = "Enabled WITHOUT NLA (High Risk)"

        checks.append(
            self.make_check(
                check_id="SEC-006",
                title="Remote Desktop Protocol (RDP) & Network Level Authentication",
                description="Check whether Remote Desktop is disabled, or if enabled, enforces Network Level Authentication (NLA).",
                status=rdp_status,
                severity=SeverityLevel.HIGH,
                finding_type=(
                    FindingType.CONFIRMED_VULNERABILITY
                    if rdp_status == CheckStatus.FAIL
                    else FindingType.CONFIGURATION_OBSERVATION
                ),
                evidence=rdp_ev,
                explanation="Exposed RDP without Network Level Authentication is one of the primary initial access vectors for ransomware operators.",
                remediation="Disable Remote Desktop if not needed, or enforce Network Level Authentication (UserAuthentication = 1) and restrict TCP 3389 via firewall.",
            )
        )
        controls.append(
            SecurityControlItem(
                control_id="SEC-006",
                domain="Remote Access",
                name="Remote Desktop (RDP)",
                state_label=rdp_lbl,
                status=rdp_status,
                severity=SeverityLevel.HIGH,
                evidence=rdp_ev,
                explanation="Controls remote interactive desktop sessions over port 3389.",
                recommendation="Disable RDP on workstations or enforce NLA + VPN.",
            )
        )

        # 7. SEC-007: UEFI Secure Boot Status
        sb_reg = payload.get("SecureBootEnabled")
        if sb_reg is None:
            sb_status = CheckStatus.NOT_ASSESSED
            sb_ev = "SecureBoot registry state not present (Legacy BIOS or unsupported VM)."
            sb_lbl = "Not Assessed / Legacy BIOS"
        elif sb_reg == 1:
            sb_status = CheckStatus.PASS
            sb_ev = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State\\UEFISecureBootEnabled = 1"
            sb_lbl = "Enabled"
        else:
            sb_status = CheckStatus.FAIL
            sb_ev = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State\\UEFISecureBootEnabled = 0"
            sb_lbl = "Disabled"

        checks.append(
            self.make_check(
                check_id="SEC-007",
                title="UEFI Secure Boot Integrity Protection",
                description="Verify that UEFI Secure Boot is enabled to prevent unsigned bootloaders and kernel rootkits.",
                status=sb_status,
                severity=SeverityLevel.HIGH,
                finding_type=(
                    FindingType.SECURITY_WEAKNESS
                    if sb_status == CheckStatus.FAIL
                    else FindingType.CONFIGURATION_OBSERVATION
                ),
                evidence=sb_ev,
                explanation="UEFI Secure Boot cryptographically verifies the OS bootloader before execution, blocking bootkits.",
                remediation="Enable Secure Boot in the system UEFI/BIOS firmware settings.",
            )
        )
        controls.append(
            SecurityControlItem(
                control_id="SEC-007",
                domain="Platform Integrity",
                name="UEFI Secure Boot",
                state_label=sb_lbl,
                status=sb_status,
                severity=SeverityLevel.HIGH,
                evidence=sb_ev,
                explanation="Verifies cryptographic signatures of boot components.",
                recommendation="Maintain UEFI Secure Boot enabled.",
            )
        )

        # 8. SEC-008: BitLocker Drive Encryption Status
        bl_state = str(payload.get("BitLockerStatus") or "NOT_ASSESSED")
        bl_detail = str(payload.get("BitLockerDetail") or "")
        if bl_state in ("ACCESS_DENIED", "NOT_ASSESSED", "UNAVAILABLE"):
            bl_status = CheckStatus.NOT_ASSESSED
            bl_lbl = "Not Assessed (Requires Admin)" if bl_state == "ACCESS_DENIED" else "Not Assessed"
            bl_ev = (
                f"Cannot query BitLocker status without Administrator elevation (Current process is_admin={is_running_as_admin()})."
                if bl_state == "ACCESS_DENIED"
                else bl_detail
            )
        elif bl_state.lower() in ("on", "1"):
            bl_status = CheckStatus.PASS
            bl_lbl = "Encrypted (Protection On)"
            bl_ev = bl_detail
        else:
            bl_status = CheckStatus.WARNING
            bl_lbl = "Unencrypted / Protection Off"
            bl_ev = bl_detail

        checks.append(
            self.make_check(
                check_id="SEC-008",
                title="BitLocker Full Disk Encryption (OS Volume C:)",
                description="Check whether the operating system drive (C:) is protected by BitLocker Drive Encryption.",
                status=bl_status,
                severity=SeverityLevel.HIGH,
                finding_type=(
                    FindingType.SECURITY_WEAKNESS
                    if bl_status in (CheckStatus.FAIL, CheckStatus.WARNING)
                    else FindingType.CONFIGURATION_OBSERVATION
                ),
                evidence=bl_ev,
                explanation="Full-disk encryption protects data at rest if a laptop or workstation is physically lost or stolen.",
                remediation=(
                    "Run WinSecAudit as Administrator to assess BitLocker, or enable BitLocker in Control Panel > BitLocker Drive Encryption."
                ),
            )
        )
        controls.append(
            SecurityControlItem(
                control_id="SEC-008",
                domain="Data Protection",
                name="BitLocker Drive Encryption (C:)",
                state_label=bl_lbl,
                status=bl_status,
                severity=SeverityLevel.HIGH,
                evidence=bl_ev,
                explanation="Encrypts the OS drive at rest using TPM + AES.",
                recommendation="Enable BitLocker or Device Encryption on C: and back up the recovery key.",
            )
        )

        # 9. SEC-009: SMBv1 Legacy Protocol Disabling
        smb1_reg = payload.get("SMB1Registry", 0)
        smb1_drv = str(payload.get("SMB1DriverState") or "NotInstalled")
        if smb1_reg == 1 or smb1_drv.lower() == "running":
            smb_status = CheckStatus.FAIL
            smb_lbl = "SMBv1 Enabled (Vulnerable)"
            smb_ev = f"LanmanServer SMB1={smb1_reg}, mrxsmb10 driver state={smb1_drv}."
        else:
            smb_status = CheckStatus.PASS
            smb_lbl = "Disabled / Not Installed"
            smb_ev = f"LanmanServer SMB1={smb1_reg}, mrxsmb10 driver state={smb1_drv}."

        checks.append(
            self.make_check(
                check_id="SEC-009",
                title="SMBv1 Legacy Protocol Deprecation",
                description="Verify that the deprecated SMBv1 protocol is disabled to prevent EternalBlue-class network exploits.",
                status=smb_status,
                severity=SeverityLevel.CRITICAL,
                finding_type=(
                    FindingType.CONFIRMED_VULNERABILITY
                    if smb_status == CheckStatus.FAIL
                    else FindingType.CONFIGURATION_OBSERVATION
                ),
                evidence=smb_ev,
                explanation="SMBv1 lacks modern cryptographic integrity protections and was exploited by WannaCry and NotPetya worms.",
                remediation="Disable SMBv1 via 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'.",
            )
        )
        controls.append(
            SecurityControlItem(
                control_id="SEC-009",
                domain="Network Security",
                name="SMBv1 Protocol Restriction",
                state_label=smb_lbl,
                status=smb_status,
                severity=SeverityLevel.CRITICAL,
                evidence=smb_ev,
                explanation="Prevents legacy SMBv1 exploitation over TCP 445.",
                recommendation="Ensure SMBv1 remains disabled and use SMBv3 with encryption.",
            )
        )

        return SecurityConfigModuleResult(checks=checks, controls=controls)
