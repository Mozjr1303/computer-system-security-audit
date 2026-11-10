"""Module C: Windows System Update & Patch Posture Auditor."""
from datetime import datetime, timezone
from typing import List, Optional
from app.auditors.base import BaseAuditor
from app.core.powershell import run_powershell
from app.schemas.audit_schemas import (
    AuditCategory,
    CheckStatus,
    FindingType,
    InstalledUpdateItem,
    PendingUpdateItem,
    SeverityLevel,
    UpdateAuditModuleResult,
)


class SystemUpdateAuditor(BaseAuditor):
    """Inspects Windows OS build, installed hotfixes, update services, and Automatic Update settings."""

    category = AuditCategory.SYSTEM_UPDATES

    def run_audit(self) -> UpdateAuditModuleResult:
        ps_script = """
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | ForEach-Object {
            $dateStr = ""
            if ($_.InstalledOn) {
                try { $dateStr = ([datetime]$_.InstalledOn).ToString("yyyy-MM-dd") } catch { $dateStr = [string]$_.InstalledOn }
            }
            [PSCustomObject]@{
                HotFixID = [string]$_.HotFixID
                Description = [string]$_.Description
                InstalledBy = [string]$_.InstalledBy
                InstalledOn = $dateStr
            }
        }
        $wuauserv = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        $usosvc = Get-Service -Name UsoSvc -ErrorAction SilentlyContinue

        $auPolicyPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
        $noAutoUpdate = $null
        $auOptions = $null
        if (Test-Path $auPolicyPath) {
            $prop = Get-ItemProperty -Path $auPolicyPath -ErrorAction SilentlyContinue
            if ($null -ne $prop.NoAutoUpdate) { $noAutoUpdate = [int]$prop.NoAutoUpdate }
            if ($null -ne $prop.AUOptions) { $auOptions = [int]$prop.AUOptions }
        }

        [PSCustomObject]@{
            OSCaption = if ($os) { [string]$os.Caption } else { "Microsoft Windows" }
            OSVersion = if ($os) { [string]$os.Version } else { "" }
            OSBuild = if ($os) { [string]$os.BuildNumber } else { "" }
            WuauservStatus = if ($wuauserv) { $wuauserv.Status.ToString() } else { "NotFound" }
            WuauservStartType = if ($wuauserv) { $wuauserv.StartType.ToString() } else { "Unknown" }
            UsoSvcStatus = if ($usosvc) { $usosvc.Status.ToString() } else { "NotFound" }
            UsoSvcStartType = if ($usosvc) { $usosvc.StartType.ToString() } else { "Unknown" }
            NoAutoUpdate = $noAutoUpdate
            AUOptions = $auOptions
            HotFixes = @($hotfixes)
        }
        """
        res = run_powershell(ps_script, timeout=20, expect_json=True)
        payload = res.parsed_json if isinstance(res.parsed_json, dict) else {}

        os_caption = payload.get("OSCaption") or "Microsoft Windows"
        os_version = payload.get("OSVersion") or "10.0"
        os_build = str(payload.get("OSBuild") or "0")
        wuauserv_status = payload.get("WuauservStatus") or "Unknown"
        wuauserv_start = payload.get("WuauservStartType") or "Unknown"
        usosvc_status = payload.get("UsoSvcStatus") or "Unknown"
        usosvc_start = payload.get("UsoSvcStartType") or "Unknown"
        no_auto_update = payload.get("NoAutoUpdate")
        au_options = payload.get("AUOptions")

        raw_hotfixes = payload.get("HotFixes") or []
        if isinstance(raw_hotfixes, dict):
            raw_hotfixes = [raw_hotfixes]

        now_date = datetime.now(timezone.utc).date()
        installed_updates: List[InstalledUpdateItem] = []
        most_recent_days: Optional[int] = None
        last_update_date: Optional[str] = None

        for hf in raw_hotfixes:
            hf_id = str(hf.get("HotFixID") or "Unknown")
            desc = str(hf.get("Description") or "Update")
            inst_by = str(hf.get("InstalledBy") or "SYSTEM")
            inst_on = str(hf.get("InstalledOn") or "")
            days_ago: Optional[int] = None
            if inst_on:
                try:
                    parsed_dt = datetime.strptime(inst_on[:10], "%Y-%m-%d").date()
                    days_ago = max(0, (now_date - parsed_dt).days)
                    if most_recent_days is None or days_ago < most_recent_days:
                        most_recent_days = days_ago
                        last_update_date = inst_on[:10]
                except ValueError:
                    pass

            installed_updates.append(
                InstalledUpdateItem(
                    hotfix_id=hf_id,
                    description=desc,
                    installed_by=inst_by,
                    installed_on=inst_on or "Date Not Recorded",
                    days_ago=days_ago,
                )
            )

        # Sort updates newest first
        installed_updates.sort(
            key=lambda x: (x.days_ago is None, x.days_ago if x.days_ago is not None else 999999)
        )

        # Query cached pending updates from Windows Update COM API (offline/fast cache query)
        pending_updates, pending_status = self._check_pending_updates_cached()

        # Determine Automatic Updates enabled state
        if no_auto_update == 1 or au_options == 1:
            auto_updates_enabled = False
        elif wuauserv_start.lower() == "disabled" and usosvc_start.lower() == "disabled":
            auto_updates_enabled = False
        else:
            auto_updates_enabled = True

        service_summary = f"wuauserv: {wuauserv_status} ({wuauserv_start}), UsoSvc: {usosvc_status} ({usosvc_start})"

        checks = self._evaluate_checks(
            os_caption=os_caption,
            os_version=os_version,
            os_build=os_build,
            installed_updates=installed_updates,
            last_update_date=last_update_date,
            most_recent_days=most_recent_days,
            wuauserv_start=wuauserv_start,
            usosvc_start=usosvc_start,
            service_summary=service_summary,
            auto_updates_enabled=auto_updates_enabled,
            no_auto_update=no_auto_update,
            pending_updates=pending_updates,
            pending_status=pending_status,
        )

        return UpdateAuditModuleResult(
            checks=checks,
            os_caption=os_caption,
            os_version=os_version,
            os_build=os_build,
            last_update_date=last_update_date,
            days_since_last_update=most_recent_days,
            automatic_updates_enabled=auto_updates_enabled,
            update_service_status=service_summary,
            installed_updates=installed_updates,
            pending_updates=pending_updates,
            pending_scan_status=pending_status,
        )

    def _check_pending_updates_cached(self):
        """Perform a fast, offline/cached check for pending Windows updates without blocking on network download."""
        ps_pending = """
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $searcher.Online = $false
        $result = $searcher.Search("IsInstalled=0 and Type='Software'")
        $items = @($result.Updates) | Select-Object -First 15 | ForEach-Object {
            $kbs = @($_.KBArticleIDs) -join ","
            [PSCustomObject]@{
                Title = [string]$_.Title
                KB = if ($kbs) { "KB$kbs" } else { "N/A" }
                Severity = if ($_.MsrcSeverity) { [string]$_.MsrcSeverity } else { "Moderate" }
                IsDownloaded = [bool]$_.IsDownloaded
            }
        }
        [PSCustomObject]@{
            Count = $result.Updates.Count
            Items = @($items)
        }
        """
        res = run_powershell(ps_pending, timeout=8, expect_json=True)
        if not res.success or not isinstance(res.parsed_json, dict):
            return [], "Offline cache query unavailable or timed out"

        raw_items = res.parsed_json.get("Items") or []
        if isinstance(raw_items, dict):
            raw_items = [raw_items]

        pending: List[PendingUpdateItem] = []
        for it in raw_items:
            pending.append(
                PendingUpdateItem(
                    title=str(it.get("Title") or "Windows Update"),
                    kb_ids=str(it.get("KB") or "N/A"),
                    severity=str(it.get("Severity") or "Unspecified"),
                    is_downloaded=bool(it.get("IsDownloaded", False)),
                )
            )
        return pending, f"Assessed via local Windows Update cache ({len(pending)} pending)"

    def _evaluate_checks(
        self,
        os_caption: str,
        os_version: str,
        os_build: str,
        installed_updates: List[InstalledUpdateItem],
        last_update_date: Optional[str],
        most_recent_days: Optional[int],
        wuauserv_start: str,
        usosvc_start: str,
        service_summary: str,
        auto_updates_enabled: bool,
        no_auto_update: Optional[int],
        pending_updates: List[PendingUpdateItem],
        pending_status: str,
    ):
        checks = []

        # UPD-001: OS Build Currency
        try:
            build_num = int(os_build)
        except ValueError:
            build_num = 0

        if build_num >= 22621:
            checks.append(
                self.make_check(
                    check_id="UPD-001",
                    title="Operating System Build Support & Currency",
                    description="Verify the Windows operating system build is actively supported by Microsoft security updates.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=f"{os_caption} (Version {os_version}, Build {os_build}) is a modern supported Windows 11 servicing build.",
                    explanation="Running an actively supported Windows build ensures the kernel and system components receive monthly security patches.",
                    remediation="No action required. Maintain current feature update servicing channel.",
                )
            )
        elif build_num >= 19045:
            checks.append(
                self.make_check(
                    check_id="UPD-001",
                    title="Operating System Build Support & Currency",
                    description="Verify the Windows operating system build is actively supported by Microsoft security updates.",
                    status=CheckStatus.WARNING,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"{os_caption} (Version {os_version}, Build {os_build}) detected.",
                    explanation="Windows 10 22H2 (Build 19045) has reached or is nearing end of mainstream servicing without Extended Security Updates (ESU).",
                    remediation="Plan an upgrade to Windows 11 (Build 22631 / 26100+) or verify ESU enrollment.",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="UPD-001",
                    title="Operating System Build Support & Currency",
                    description="Verify the Windows operating system build is actively supported by Microsoft security updates.",
                    status=CheckStatus.FAIL,
                    severity=SeverityLevel.CRITICAL,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"Legacy OS build detected: {os_caption} (Build {os_build}).",
                    explanation="End-of-life Windows builds no longer receive patches for newly discovered zero-day vulnerabilities.",
                    remediation="Upgrade the operating system to a currently supported Windows release.",
                )
            )

        # UPD-002: Installed Hotfixes & Patch Recency
        if not installed_updates:
            checks.append(
                self.make_check(
                    check_id="UPD-002",
                    title="Installed Security Updates & Patch Recency",
                    description="Verify that Windows cumulative and security hotfixes are installed and recent.",
                    status=CheckStatus.FAIL,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence="Get-HotFix returned 0 installed hotfixes.",
                    explanation="No installed hotfixes were found, indicating the system may be unpatched since initial installation.",
                    remediation="Open Settings > Windows Update and check for updates immediately.",
                )
            )
        elif most_recent_days is not None and most_recent_days <= 45:
            latest_kb = installed_updates[0].hotfix_id
            checks.append(
                self.make_check(
                    check_id="UPD-002",
                    title="Installed Security Updates & Patch Recency",
                    description="Verify that Windows cumulative and security hotfixes are installed and recent.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=f"{len(installed_updates)} hotfixes installed. Latest update {latest_kb} installed on {last_update_date} ({most_recent_days} days ago).",
                    explanation="Microsoft releases cumulative security updates monthly (Patch Tuesday). Updates within the last 45 days indicate healthy patch hygiene.",
                    remediation="Continue applying monthly cumulative updates.",
                )
            )
        elif most_recent_days is not None and most_recent_days <= 90:
            latest_kb = installed_updates[0].hotfix_id
            checks.append(
                self.make_check(
                    check_id="UPD-002",
                    title="Installed Security Updates & Patch Recency",
                    description="Verify that Windows cumulative and security hotfixes are installed and recent.",
                    status=CheckStatus.WARNING,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"Latest recorded hotfix ({latest_kb}) was installed on {last_update_date} ({most_recent_days} days ago).",
                    explanation="More than 45 days have elapsed since the last recorded hotfix installation, suggesting at least one Patch Tuesday cycle may have been missed.",
                    remediation="Run Windows Update to check for and install the latest cumulative security update.",
                )
            )
        else:
            ev = (
                f"Latest recorded hotfix ({installed_updates[0].hotfix_id}) was installed on {last_update_date} ({most_recent_days} days ago)."
                if most_recent_days is not None
                else f"{len(installed_updates)} hotfixes found, but installation dates were not recorded by WMI."
            )
            status = CheckStatus.FAIL if (most_recent_days and most_recent_days > 90) else CheckStatus.WARNING
            checks.append(
                self.make_check(
                    check_id="UPD-002",
                    title="Installed Security Updates & Patch Recency",
                    description="Verify that Windows cumulative and security hotfixes are installed and recent.",
                    status=status,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=ev,
                    explanation="Outdated systems lacking recent cumulative updates are exposed to publicly disclosed CVEs.",
                    remediation="Trigger a manual Windows Update check via Settings > Windows Update.",
                )
            )

        # UPD-003: Windows Update Service Configuration
        if wuauserv_start.lower() == "disabled" or usosvc_start.lower() == "disabled":
            checks.append(
                self.make_check(
                    check_id="UPD-003",
                    title="Windows Update Services Availability",
                    description="Ensure Windows Update (wuauserv) and Update Orchestrator (UsoSvc) services are not disabled.",
                    status=CheckStatus.FAIL,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=service_summary,
                    explanation="If wuauserv or UsoSvc is disabled, Windows cannot download or apply critical security updates or Defender definition updates.",
                    remediation="Set Windows Update (wuauserv) and Update Orchestrator (UsoSvc) Startup Type to Manual (Trigger Start) or Automatic.",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="UPD-003",
                    title="Windows Update Services Availability",
                    description="Ensure Windows Update (wuauserv) and Update Orchestrator (UsoSvc) services are not disabled.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=service_summary,
                    explanation="Windows Update services are enabled (Manual Trigger-Start or Automatic is standard on Windows 10/11).",
                    remediation="No action required.",
                )
            )

        # UPD-004: Automatic Updates Policy
        if not auto_updates_enabled:
            checks.append(
                self.make_check(
                    check_id="UPD-004",
                    title="Automatic Updates Configuration",
                    description="Verify that Automatic Updates are enabled via Windows policy and service configuration.",
                    status=CheckStatus.FAIL,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"Automatic Updates disabled (NoAutoUpdate={no_auto_update}, {service_summary}).",
                    explanation="Disabling automatic updates leaves the host vulnerable until an administrator manually intervenes.",
                    remediation="Enable Automatic Updates in Group Policy (Configure Automatic Updates = Enabled) or remove NoAutoUpdate registry policy.",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="UPD-004",
                    title="Automatic Updates Configuration",
                    description="Verify that Automatic Updates are enabled via Windows policy and service configuration.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.HIGH,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=f"Automatic Updates policy is active (NoAutoUpdate={no_auto_update or 0}).",
                    explanation="Automatic updates ensure critical OS and Defender security patches are delivered promptly.",
                    remediation="No action required.",
                )
            )

        # UPD-005: Pending Updates Assessment
        if "unavailable" in pending_status.lower():
            checks.append(
                self.make_check(
                    check_id="UPD-005",
                    title="Pending Windows Updates Queue",
                    description="Check the local Windows Update agent cache for uninstalled pending updates.",
                    status=CheckStatus.NOT_ASSESSED,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence=pending_status,
                    explanation="The Windows Update COM offline cache could not be queried within the audit timeout.",
                    remediation="Review Windows Update status directly in Windows Settings.",
                )
            )
        elif pending_updates:
            titles = "; ".join(f"{p.title} ({p.kb_ids})" for p in pending_updates[:3])
            checks.append(
                self.make_check(
                    check_id="UPD-005",
                    title="Pending Windows Updates Queue",
                    description="Check the local Windows Update agent cache for uninstalled pending updates.",
                    status=CheckStatus.WARNING,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.SECURITY_WEAKNESS,
                    evidence=f"{len(pending_updates)} pending update(s) detected in local cache: {titles}",
                    explanation="Pending updates that have been detected or downloaded but not yet installed leave known vulnerabilities unpatched.",
                    remediation="Install pending updates and complete any required system reboot.",
                )
            )
        else:
            checks.append(
                self.make_check(
                    check_id="UPD-005",
                    title="Pending Windows Updates Queue",
                    description="Check the local Windows Update agent cache for uninstalled pending updates.",
                    status=CheckStatus.PASS,
                    severity=SeverityLevel.MEDIUM,
                    finding_type=FindingType.CONFIGURATION_OBSERVATION,
                    evidence="0 pending software updates found in the local Windows Update cache.",
                    explanation="No uninstalled updates are waiting in the local update queue.",
                    remediation="No action required.",
                )
            )

        return checks
