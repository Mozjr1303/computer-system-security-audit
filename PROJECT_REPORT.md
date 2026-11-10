# UNIVERSITY CYBERSECURITY PROJECT REPORT
## Security Audit of a Computer System (WinSecAudit)

---

### 1. Executive Summary & Abstract

This project presents the design, implementation, and empirical evaluation of **WinSecAudit**, an automated, read-only Windows Security Auditing and Compliance System. Developed using a decoupled three-tier architecture (**React 18 + TypeScript + Tailwind CSS** frontend, **Python 3.11 + FastAPI** backend, and **SQLite** persistence), WinSecAudit inspects a live Windows workstation across five mandatory cybersecurity domains:

1. **User Accounts & Password Policies** (`20 points`)
2. **System Updates & Patch Currency** (`20 points`)
3. **File & Directory NTFS Permissions** (`20 points`)
4. **Running Windows Services & Privilege Escalation Vectors** (`15 points`)
5. **Host Security Configurations (Defender, Firewall, UAC, RDP, Secure Boot, BitLocker, SMBv1)** (`25 points`)

Unlike static checklists or simulated tools, WinSecAudit executes 31 real, non-destructive host inspections via hardened PowerShell, WMI/CIM, Windows Registry, and NTFS Access Control List (ACL) queries. When executed against the target Windows 11 workstation (Build `26200`), the system achieved an overall security posture score of **86.0 / 100 (`Elevated Risk — Action Required`)**, identifying **24 compliant controls**, **3 failed checks** (including a `CWE-428` Unquoted Service Binary Path vulnerability and an account with `PasswordRequired=False`), **2 warnings**, and **2 elevation-restricted checks** (`Not Assessed`).

---

### 2. System Architecture & Technology Stack

#### 2.1 Architectural Layers
1. **Presentation Layer (`frontend/`):**
   - Built with **React 18**, **TypeScript**, **Vite 6**, **Tailwind CSS v4**, **Lucide React**, and **Recharts**.
   - Provides 10 specialized cybersecurity views: Dashboard, Live Audit Scanner, User Accounts, System Updates, File Permissions, Running Services, Security Configuration, Audit Reports, Audit History, and Scoring Methodology Settings.
2. **Application & Auditing Layer (`backend/`):**
   - Built with **Python 3.11**, **FastAPI**, **Pydantic v2**, and **ReportLab**.
   - Enforces a loopback-only security middleware (`127.0.0.1` / `::1`) and executes read-only PowerShell script blocks via `subprocess.run(..., shell=False)` with a strict 15-verb blocklist (`FORBIDDEN_VERBS`).
3. **Persistence Layer (`backend/audit_system.db`):**
   - Built with **SQLite** and **SQLAlchemy 2.0 ORM** across four normalized tables: `audit_sessions`, `audit_findings`, `category_scores`, and `report_metadata`.

---

### 3. Technical Methodology Across the Five Audit Categories

#### 3.1 Module B: User Account Audit (`users_auditor.py` — 20 Points)
- **Telemetry Sources:** `Get-LocalUser`, `Get-LocalGroupMember -Group 'Administrators'`, ADSI fallback (`WinNT://.../Administrators,group`), and `net accounts`.
- **Checks Performed (`USR-001` – `USR-007`):**
  - `USR-001`: Verifies the built-in `Guest` account (RID `-501`) is disabled.
  - `USR-002`: Checks whether the default built-in `Administrator` account (RID `-500`) is disabled.
  - `USR-003`: Evaluates Principle of Least Privilege by counting active members of the local `Administrators` group.
  - `USR-004`: Flags any enabled local user account where `PasswordRequired == False` (`Critical` Confirmed Vulnerability).
  - `USR-005`: Flags active user accounts where `PasswordNeverExpires == True`.
  - `USR-006`: Evaluates system-wide Minimum Password Length against security benchmarks ($\ge 8$ / $\ge 12$ characters).
  - `USR-007`: Evaluates Account Lockout Threshold brute-force protection.

#### 3.2 Module C: System Update Audit (`updates_auditor.py` — 20 Points)
- **Telemetry Sources:** `Win32_OperatingSystem`, `Get-HotFix`, `Get-Service wuauserv, UsoSvc`, Registry policy `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, and the `Microsoft.Update.Session` COM interface.
- **Checks Performed (`UPD-001` – `UPD-005`):**
  - `UPD-001`: Verifies the OS build number is in active Microsoft security servicing.
  - `UPD-002`: Computes the number of days elapsed since the most recent cumulative security hotfix (`KB...`) was installed.
  - `UPD-003`: Verifies that Windows Update (`wuauserv`) and Update Orchestrator (`UsoSvc`) services are not disabled.
  - `UPD-004`: Verifies that Automatic Updates are not disabled via Registry or Group Policy (`NoAutoUpdate`).
  - `UPD-005`: Queries the local offline Windows Update cache for uninstalled pending updates.

#### 3.3 Module D: File & Permission Audit (`permissions_auditor.py` — 20 Points)
- **Telemetry Sources:** `Get-Acl -LiteralPath` across six critical system paths:
  1. `C:\Windows\System32`
  2. `C:\Windows\System32\drivers\etc\hosts`
  3. `C:\Program Files`
  4. `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
  5. `C:\Users\Public`
  6. `C:\Windows\Temp`
- **Checks Performed (`PERM-001` – `PERM-005`):**
  - Inspects every Access Control Entry (ACE) for `Everyone`, `BUILTIN\Users`, `Authenticated Users`, and `Anonymous Logon`, flagging any `Allow` rule granting `FullControl`, `Modify`, `Write`, `WriteData`, `ChangePermissions`, or `TakeOwnership` on sensitive system paths.

#### 3.4 Module E: Running Services Audit (`services_auditor.py` — 15 Points)
- **Telemetry Sources:** `Get-CimInstance -ClassName Win32_Service`.
- **Checks Performed (`SVC-001` – `SVC-005`):**
  - `SVC-001`: Scans all service `PathName` properties for **CWE-428 Unquoted Search Path or Element** vulnerabilities (paths not enclosed in double quotes that contain whitespace prior to `.exe`).
  - `SVC-002`: Verifies the `RemoteRegistry` service is stopped and disabled.
  - `SVC-003`: Verifies legacy cleartext or amplification-prone services (`TlntSvr`, `FTPSVC`, `SNMP`, `SimpTcp`) are not running.
  - `SVC-004`: Evaluates `Print Spooler` (`Spooler`) `LocalSystem` exposure.
  - `SVC-005`: Audits third-party background services executing outside `C:\Windows` under unrestricted `LocalSystem` privileges.

#### 3.5 Module F: Security Configuration Audit (`security_auditor.py` — 25 Points)
- **Telemetry Sources:** `Get-MpComputerStatus`, `Get-NetFirewallProfile`, `Get-BitLockerVolume`, and Windows Registry (`Policies\System`, `Terminal Server`, `SecureBoot\State`, `LanmanServer\Parameters`).
- **Checks Performed (`SEC-001` – `SEC-009`):**
  - `SEC-001`: Windows Defender Antivirus & Real-Time Protection status.
  - `SEC-002`: Windows Defender Security Intelligence signature age ($\le 3$ days).
  - `SEC-003`: Windows Defender Tamper Protection (`IsTamperProtected`).
  - `SEC-004`: Windows Defender Firewall across `Domain`, `Private`, and `Public` profiles.
  - `SEC-005`: User Account Control (`EnableLUA`, `ConsentPromptBehaviorAdmin`, `PromptOnSecureDesktop`).
  - `SEC-006`: Remote Desktop (`fDenyTSConnections`) and Network Level Authentication (`UserAuthentication`).
  - `SEC-007`: UEFI Secure Boot (`UEFISecureBootEnabled`).
  - `SEC-008`: BitLocker Drive Encryption on OS Volume `C:`.
  - `SEC-009`: SMBv1 legacy protocol deprecation (`SMB1` registry & `mrxsmb10` driver state).

---

### 4. Transparent 100-Point Security Scoring Methodology

Each category $c$ is assigned a maximum weight $W_c$:
- User Accounts: $W_{\text{users}} = 20$
- System Updates: $W_{\text{updates}} = 20$
- File Permissions: $W_{\text{permissions}} = 20$
- Running Services: $W_{\text{services}} = 15$
- Security Configurations: $W_{\text{security}} = 25$

Each check $i$ has a severity weight $w_i \in \{10, 6, 3, 1, 0\}$ corresponding to `Critical` ($10$), `High` ($6$), `Medium` ($3$), `Low` ($1$), and `Informational` ($0$).
- Checks returning `NOT_ASSESSED` (e.g., when Administrator elevation is required) or `INFO` are excluded from the denominator.
- For assessed checks:
  - `PASS` awards $1.0 \times w_i$
  - `WARNING` awards $0.5 \times w_i$
  - `FAIL` awards $0.0 \times w_i$

The category score is computed as:
$$\text{Score}_c = W_c \times \frac{\sum_{i \in \text{Assessed}(c)} m_i \cdot w_i}{\sum_{i \in \text{Assessed}(c)} w_i}$$

And the overall security score is:
$$\text{Overall Score} = \sum_{c} \text{Score}_c \in [0, 100]$$

---

### 5. Empirical Audit Findings & Remediation Summary

During the host audit on Windows 11 Build `26200` (**Overall Score: `86.0 / 100`**), the following actionable weaknesses and vulnerabilities were identified:

| Check ID | Category | Status | Severity | Classification | Finding Summary & Evidence | Recommended Remediation |
| :--- | :--- | :---: | :---: | :--- | :--- | :--- |
| **`USR-004`** | User Accounts | `FAIL` | **Critical** | Confirmed Vulnerability | Enabled local administrator account has `PasswordRequired = False`. | Enforce a local password requirement (`Set-LocalUser -PasswordRequired $true`) alongside Windows Hello PIN. |
| **`SVC-001`** | Running Services | `FAIL` | **High** | Confirmed Vulnerability | `UpcElevationService` has an unquoted binary path containing spaces (`C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher Core\UpcElevationService.exe`). | Enclose the `ImagePath` registry value in double quotes under `HKLM:\SYSTEM\CurrentControlSet\Services\UpcElevationService`. |
| **`USR-006`** | User Accounts | `FAIL` | **High** | Security Weakness | `net accounts` reports `Minimum password length: 0 characters`. | Configure Minimum Password Length to at least 12 characters (`net accounts /minpwlen:12`). |
| **`SVC-005`** | Running Services | `WARNING` | **Medium** | Security Weakness | 14 third-party services are executing as `LocalSystem` outside `C:\Windows`. | Audit third-party background services and remove unused software agents. |
| **`SVC-004`** | Running Services | `WARNING` | **Low** | Configuration Observation | `Print Spooler` (`Spooler`) is running as `LocalSystem` (`StartMode: Auto`). | Disable Print Spooler if local/network printing is not required on the workstation. |
| **`SEC-008`** | Security Config | `NOT_ASSESSED` | **High** | Configuration Observation | BitLocker WMI/cmdlet inspection requires Administrator elevation. | Run WinSecAudit as Administrator to verify full-disk encryption on Volume `C:`. |

---

### 6. Conclusion

WinSecAudit demonstrates how defensive cybersecurity engineering can combine native Windows telemetry (PowerShell, CIM/WMI, Registry, and NTFS ACLs) with modern full-stack web technologies (FastAPI, Pydantic, SQLite, React, TypeScript, and ReportLab) to deliver accurate, transparent, and safe host security posture assessments without risking system stability.
