"""Hardened, read-only PowerShell and Windows command execution engine."""
import ctypes
import json
import logging
import subprocess
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger("winsecaudit.powershell")

# Block any destructive or state-changing PowerShell verbs
FORBIDDEN_VERBS = (
    "Stop-Service",
    "Set-Service",
    "Remove-Item",
    "Set-Acl",
    "Disable-LocalUser",
    "Enable-LocalUser",
    "Remove-LocalUser",
    "New-LocalUser",
    "Set-LocalUser",
    "Set-NetFirewallProfile",
    "Set-MpPreference",
    "Install-WindowsUpdate",
    "Restart-Computer",
    "Stop-Computer",
    "Set-ExecutionPolicy",
    "Invoke-Expression",
)


@dataclass
class PSResult:
    success: bool
    stdout: str
    stderr: str
    return_code: int
    access_denied: bool = False
    timed_out: bool = False
    parsed_json: Optional[Any] = None


def is_running_as_admin() -> bool:
    """Check if the current Python process has Windows Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_powershell(
    script_block: str,
    timeout: int = 25,
    expect_json: bool = False,
) -> PSResult:
    """
    Execute a predefined read-only PowerShell command safely with shell=False.
    Never accepts user-supplied input.
    """
    for forbidden in FORBIDDEN_VERBS:
        if forbidden.lower() in script_block.lower():
            raise ValueError(f"Security policy violation: forbidden verb '{forbidden}' in PowerShell command.")

    clean_block = script_block.strip()
    if expect_json and "ConvertTo-Json" not in clean_block:
        full_command = f"& {{\n{clean_block}\n}} | ConvertTo-Json -Depth 5 -Compress"
    else:
        full_command = clean_block

    # Force UTF-8 output encoding for clean JSON parsing
    wrapped_script = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;\n"
        "$WarningPreference = 'SilentlyContinue';\n"
        "$ProgressPreference = 'SilentlyContinue';\n"
        f"{full_command}"
    )

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        wrapped_script,
    ]

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()
        combined_err = f"{stderr} {stdout}".lower()
        access_denied = any(
            phrase in combined_err
            for phrase in (
                "access is denied",
                "unauthorizedaccess",
                "requires elevation",
                "privilege is not held",
                "permissiondenied",
                "0x80070005",
            )
        )

        parsed = None
        if expect_json and stdout:
            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError:
                for idx, ch in enumerate(stdout):
                    if ch in ("{", "["):
                        try:
                            parsed = json.loads(stdout[idx:])
                        except json.JSONDecodeError:
                            parsed = None
                        break

        return PSResult(
            success=(completed.returncode == 0),
            stdout=stdout,
            stderr=stderr,
            return_code=completed.returncode,
            access_denied=access_denied,
            parsed_json=parsed,
        )
    except subprocess.TimeoutExpired:
        logger.warning("PowerShell command timed out after %ds", timeout)
        return PSResult(
            success=False,
            stdout="",
            stderr=f"Command timed out after {timeout} seconds.",
            return_code=-1,
            timed_out=True,
        )
    except Exception as exc:
        logger.error("Error running PowerShell command: %s", exc)
        return PSResult(
            success=False,
            stdout="",
            stderr=str(exc),
            return_code=-1,
        )
