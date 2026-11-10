"""Application configuration and security constants for WinSecAudit."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "generated_reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_PATH = BASE_DIR / "audit_system.db"
DATABASE_URL = f"sqlite:///{DATABASE_PATH.as_posix()}"

APP_TITLE = "WinSecAudit - Windows Security Auditing System"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = (
    "Read-only Windows Host Security Posture Assessment Engine "
    "inspecting User Accounts, System Updates, File Permissions, Running Services, "
    "and Security Configurations."
)

# Strictly allow only local frontend origins
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
]

# Category maximum points (Total = 100)
CATEGORY_WEIGHTS = {
    "user_accounts": 20,
    "system_updates": 20,
    "file_permissions": 20,
    "running_services": 15,
    "security_config": 25,
}
