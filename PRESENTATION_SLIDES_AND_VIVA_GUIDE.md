# UNIVERSITY PRESENTATION SLIDE DECK & VIVA DEFENSE GUIDE
## Project: Security Audit of a Computer System (WinSecAudit)

Use this guide to structure your presentation slides and answer technical questions from your lecturer or examination panel.

---

## PART 1: 8-SLIDE PRESENTATION OUTLINE

### Slide 1: Title & Project Objective
- **Title:** WinSecAudit — Automated Windows Host Security Posture & Compliance Auditing System
- **Objective:** Design and build a real-time, read-only security auditing application that inspects a Windows computer across 5 core cybersecurity domains, quantifies risk on a transparent 100-point scale, and generates actionable PDF & JSON audit reports.

### Slide 2: The Problem & Motivation
- **Why Host Security Auditing Matters:**
  - Misconfigured local accounts, missing patches, weak NTFS permissions, unquoted service paths, and disabled endpoint protections are the primary vectors for privilege escalation and ransomware lateral movement.
- **Key Engineering Challenge:**
  - How do we inspect deep Windows OS telemetry accurately **without** modifying system state, exposing passwords, or introducing command injection risks?

### Slide 3: System Architecture & Technology Stack
- **Presentation Layer:** React 18, TypeScript, Vite, Tailwind CSS, Recharts, Lucide Icons (`127.0.0.1:5173`).
- **Auditing & API Layer:** Python 3.11, FastAPI, Pydantic v2, ReportLab PDF Engine (`127.0.0.1:8000`).
- **OS Telemetry & Persistence Layer:** Windows PowerShell 5.1 (`ConvertTo-Json`), WMI/CIM, Windows Registry, NTFS ACLs, and SQLite (`SQLAlchemy 2.0`).

### Slide 4: The Five Audited Security Domains (31 Real Checks)
1. **User Accounts (20 pts / 7 checks):** Local users, `Administrators` group, `Guest` & RID-500 status, `PasswordRequired=False`, `PasswordNeverExpires`, and `net accounts` lockout/length policies.
2. **System Updates (20 pts / 5 checks):** OS servicing build currency, installed KB hotfixes (`Get-HotFix`), patch recency, `wuauserv`/`UsoSvc` status, and Automatic Update policies.
3. **File Permissions (20 pts / 5 checks):** NTFS ACL (`Get-Acl`) inspection across 6 sensitive directories (`System32`, `hosts`, `Program Files`, `StartUp`, `Users\Public`, `Windows\Temp`).
4. **Running Services (15 pts / 5 checks):** Inspection of 289+ services for `CWE-428` Unquoted Service Binary Paths, `RemoteRegistry`, legacy daemons, `Print Spooler`, and third-party `LocalSystem` services.
5. **Security Configuration (25 pts / 9 checks):** Windows Defender Real-Time Protection, signature age, Tamper Protection, Firewall profiles, UAC Secure Desktop, RDP/NLA, UEFI Secure Boot, BitLocker, and SMBv1.

### Slide 5: Transparent 100-Point Scoring Methodology
- **Weighted Formula:**
  - Severity weights: `Critical = 10`, `High = 6`, `Medium = 3`, `Low = 1`, `Informational = 0`.
  - Status multipliers: `PASS = 100%`, `WARNING = 50%`, `FAIL = 0%`.
- **Fair Handling of Privilege Boundaries:**
  - Checks returning `NOT_ASSESSED` (such as BitLocker under Standard User context) are excluded from the denominator so unprivileged execution neither penalizes nor inflates the score.

### Slide 6: Real Empirical Findings on Target Host (`86.0 / 100`)
- **Target System:** Windows 11 Home (Build `26200`)
- **Key Discoveries:**
  - **Critical (`USR-004`):** Active local admin account had `PasswordRequired = False`.
  - **High (`SVC-001` — CWE-428):** Discovered unquoted service binary path with spaces in `UpcElevationService.exe`.
  - **High (`USR-006`):** Minimum password length policy set to `0` characters.
  - **Compliant (`PASS`):** Defender Real-Time & Tamper Protection active, all 3 Firewall profiles enabled, UAC Secure Desktop active, UEFI Secure Boot enabled, SMBv1 disabled, and all 48 NTFS ACEs across 6 critical paths properly restricted.

### Slide 7: Defensive Security Engineering of the Tool Itself
- **Read-Only by Design:** `FORBIDDEN_VERBS` static guard blocks mutating cmdlets (`Stop-Service`, `Set-Acl`, `Disable-LocalUser`, etc.).
- **Zero Command Injection Surface:** Frontend cannot pass shell parameters; `subprocess.run(..., shell=False)` executes fixed script blocks.
- **Localhost Loopback Isolation:** FastAPI middleware blocks any non-loopback HTTP requests with `403 Forbidden`.

### Slide 8: Live Demonstration & Q&A
- Transition directly to the browser at `http://127.0.0.1:5173` and the generated 14-section PDF report.

---

## PART 2: LECTURER VIVA Q&A CHEAT SHEET

### Q1: *"How do you ensure your web application cannot be exploited to run arbitrary PowerShell commands on the host?"*
**Answer:**
1. The REST API endpoints (`POST /api/audit/start`, `GET /api/audit/users`, etc.) take **zero** command strings or file paths from the user.
2. In `backend/app/core/powershell.py`, all commands are executed via `subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ...], shell=False)`.
3. A static security guard (`FORBIDDEN_VERBS`) inspects every script block before execution and raises a `ValueError` if any state-modifying verb (`Set-`, `Stop-`, `Remove-`, `Disable-`, `Invoke-Expression`) is present.
4. FastAPI middleware (`enforce_local_access_only`) restricts API access strictly to `127.0.0.1` / `::1`.

---

### Q2: *"What is an Unquoted Service Path vulnerability (`SVC-001` / `CWE-428`), and how did your scanner find it on your laptop?"*
**Answer:**
- When a Windows service executable path contains spaces and is **not** wrapped in quotation marks — for example, `C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher Core\UpcElevationService.exe` — the Windows Service Control Manager (`services.exe`) parses spaces as argument delimiters and attempts to execute:
  1. `C:\Program.exe`
  2. `C:\Program Files (x86)\Ubisoft\Ubisoft.exe`
  3. `C:\Program Files (x86)\Ubisoft\Ubisoft Game.exe`
- If an attacker has write permissions to any of those parent folders, they can plant a malicious executable that Windows will run as `LocalSystem`.
- Our scanner in `services_auditor.py` inspects the `PathName` property of all 289 services via `Win32_Service`, strips arguments after `.exe`, and flags any path that does not start with `"` and contains whitespace before `.exe`.

---

### Q3: *"What happens when the application is run as a Standard User vs. Administrator?"*
**Answer:**
- The backend detects elevation using `ctypes.windll.shell32.IsUserAnAdmin()`.
- We engineered the checks to use standard-user accessible APIs wherever possible (for example, reading `HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State` for UEFI Secure Boot instead of requiring elevated `Confirm-SecureBootUEFI`).
- For checks that strictly require elevation by Windows kernel design — such as `Get-BitLockerVolume` (`SEC-008`) — the scanner catches the `Access Denied` exception, classifies the check as `NOT_ASSESSED` (rather than falsely claiming BitLocker is disabled), and excludes it from the scoring denominator.
