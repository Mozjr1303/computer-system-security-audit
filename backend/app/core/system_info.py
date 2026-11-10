"""Host computer and Windows OS information collector."""
from datetime import datetime, timezone
import getpass
import platform
import socket
import psutil

from app.core.powershell import is_running_as_admin, run_powershell
from app.schemas.audit_schemas import SystemInfoSchema


def collect_system_info() -> SystemInfoSchema:
    """Collect real hardware, OS, build, and privilege information from the Windows host."""
    ps_script = """
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    [PSCustomObject]@{
        OSCaption = if ($os) { $os.Caption } else { "" }
        OSVersion = if ($os) { $os.Version } else { "" }
        BuildNumber = if ($os) { [string]$os.BuildNumber } else { "" }
        Architecture = if ($os) { $os.OSArchitecture } else { "" }
        Manufacturer = if ($cs) { $cs.Manufacturer } else { "" }
        Model = if ($cs) { $cs.Model } else { "" }
        Domain = if ($cs) { $cs.Domain } else { "WORKGROUP" }
        PartOfDomain = if ($cs) { [bool]$cs.PartOfDomain } else { $false }
        CPUName = if ($cpu) { $cpu.Name } else { "" }
        PSVersion = $PSVersionTable.PSVersion.ToString()
    }
    """
    res = run_powershell(ps_script, timeout=15, expect_json=True)
    data = res.parsed_json if isinstance(res.parsed_json, dict) else {}

    boot_ts = psutil.boot_time()
    boot_dt = datetime.fromtimestamp(boot_ts, tz=timezone.utc)
    now_dt = datetime.now(timezone.utc)
    uptime_hours = round((now_dt - boot_dt).total_seconds() / 3600.0, 2)
    ram_total_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2)

    domain_str = data.get("Domain") or "WORKGROUP"
    part_of_domain = data.get("PartOfDomain", False)
    domain_label = f"Domain: {domain_str}" if part_of_domain else f"Workgroup: {domain_str}"

    return SystemInfoSchema(
        hostname=socket.gethostname(),
        os_name=data.get("OSCaption") or f"Windows {platform.release()}",
        os_version=data.get("OSVersion") or platform.version(),
        os_build=str(data.get("BuildNumber") or platform.version().split(".")[-1]),
        architecture=data.get("Architecture") or platform.machine(),
        manufacturer=data.get("Manufacturer") or "Generic PC",
        model=data.get("Model") or "Standard System",
        domain_or_workgroup=domain_label,
        current_user=getpass.getuser(),
        is_admin=is_running_as_admin(),
        powershell_version=data.get("PSVersion") or "5.1",
        cpu_Model=(data.get("CPUName") or platform.processor() or "x64 Processor").strip(),
        cpu_cores=psutil.cpu_count(logical=True) or 1,
        ram_total_gb=ram_total_gb,
        boot_time=boot_dt.isoformat(),
        uptime_hours=uptime_hours,
        collected_at=now_dt.isoformat(),
    )
