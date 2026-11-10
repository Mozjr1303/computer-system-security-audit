"""Pydantic v2 schemas for Windows Security Audit System."""
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    INFO = "INFO"
    NOT_ASSESSED = "NOT_ASSESSED"


class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class FindingType(str, Enum):
    SECURITY_WEAKNESS = "Security Weakness"
    CONFIRMED_VULNERABILITY = "Confirmed Vulnerability"
    CONFIGURATION_OBSERVATION = "Configuration Observation"


class AuditCategory(str, Enum):
    USER_ACCOUNTS = "user_accounts"
    SYSTEM_UPDATES = "system_updates"
    FILE_PERMISSIONS = "file_permissions"
    RUNNING_SERVICES = "running_services"
    SECURITY_CONFIG = "security_config"


class SystemInfoSchema(BaseModel):
    hostname: str
    os_name: str
    os_version: str
    os_build: str
    architecture: str
    manufacturer: str
    model: str
    domain_or_workgroup: str
    current_user: str
    is_admin: bool
    powershell_version: str
    cpu_Model: str = Field(default="Unknown CPU")
    cpu_cores: int
    ram_total_gb: float
    boot_time: str
    uptime_hours: float
    collected_at: str


class AuditCheckResult(BaseModel):
    check_id: str
    category: AuditCategory
    title: str
    description: str
    status: CheckStatus
    severity: SeverityLevel
    finding_type: FindingType
    evidence: str
    explanation: str
    remediation: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


# Module B: Detailed User Account Item
class UserAccountDetail(BaseModel):
    username: str
    enabled: bool
    account_type: str
    is_admin: bool
    password_required: bool
    password_never_expires: bool
    last_logon: Optional[str] = None
    sid: Optional[str] = None
    description: Optional[str] = None
    identified_risks: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    risk_level: SeverityLevel = SeverityLevel.INFORMATIONAL


class PasswordPolicySummary(BaseModel):
    min_password_length: Optional[int] = None
    max_password_age_days: Optional[str] = None
    min_password_age_days: Optional[int] = None
    lockout_threshold: Optional[str] = None
    lockout_duration_mins: Optional[str] = None
    lockout_observation_mins: Optional[str] = None
    password_history_length: Optional[str] = None


class UserAuditModuleResult(BaseModel):
    checks: List[AuditCheckResult]
    accounts: List[UserAccountDetail]
    password_policy: PasswordPolicySummary
    total_accounts: int
    enabled_accounts: int
    admin_accounts: int


# Module C: Detailed System Update Item
class InstalledUpdateItem(BaseModel):
    hotfix_id: str
    description: str
    installed_by: str
    installed_on: str
    days_ago: Optional[int] = None


class PendingUpdateItem(BaseModel):
    title: str
    kb_ids: str
    severity: str
    is_downloaded: bool


class UpdateAuditModuleResult(BaseModel):
    checks: List[AuditCheckResult]
    os_caption: str
    os_version: str
    os_build: str
    last_update_date: Optional[str] = None
    days_since_last_update: Optional[int] = None
    automatic_updates_enabled: Optional[bool] = None
    update_service_status: str
    installed_updates: List[InstalledUpdateItem]
    pending_updates: List[PendingUpdateItem] = Field(default_factory=list)
    pending_scan_status: str = "Not Scanned"


# Module D: Detailed Permission Item
class PermissionEntryItem(BaseModel):
    path: str
    exists: bool
    accessible: bool
    owner: str
    identity: str
    rights: str
    access_control_type: str
    is_inherited: bool
    is_risky: bool
    security_concern: str
    recommended_action: str
    severity: SeverityLevel


class PermissionAuditModuleResult(BaseModel):
    checks: List[AuditCheckResult]
    inspected_paths_count: int
    risky_permissions_count: int
    entries: List[PermissionEntryItem]


# Module E: Detailed Running Service Item
class ServiceItemDetail(BaseModel):
    name: str
    display_name: str
    state: str
    start_mode: str
    start_name: str
    path_name: str
    process_id: int
    is_elevated_system: bool
    has_unquoted_path_risk: bool
    is_risky_service: bool
    risk_level: SeverityLevel
    risk_explanation: str
    recommendation: str


class ServiceAuditModuleResult(BaseModel):
    checks: List[AuditCheckResult]
    total_services: int
    running_services: int
    stopped_services: int
    elevated_running_services: int
    risky_services_count: int
    services: List[ServiceItemDetail]


# Module F: Detailed Security Configuration Item
class SecurityControlItem(BaseModel):
    control_id: str
    domain: str
    name: str
    state_label: str
    status: CheckStatus
    severity: SeverityLevel
    evidence: str
    explanation: str
    recommendation: str


class SecurityConfigModuleResult(BaseModel):
    checks: List[AuditCheckResult]
    controls: List[SecurityControlItem]


# Scoring & Overall Audit Result
class CategoryScoreSummary(BaseModel):
    category: AuditCategory
    category_label: str
    max_points: float
    earned_points: float
    percentage: float
    total_checks: int
    passed_checks: int
    failed_checks: int
    warning_checks: int
    info_checks: int
    not_assessed_checks: int


class ScoreBreakdownResult(BaseModel):
    overall_score: float
    max_score: float = 100.0
    risk_rating: str
    executive_summary: str
    total_checks: int
    passed_checks: int
    failed_checks: int
    warning_checks: int
    info_checks: int
    not_assessed_checks: int
    critical_findings_count: int
    high_findings_count: int
    medium_findings_count: int
    low_findings_count: int
    categories: Dict[str, CategoryScoreSummary]
    methodology_notes: str


class FullAuditResultSchema(BaseModel):
    audit_id: str
    started_at: str
    completed_at: str
    duration_seconds: float
    system_info: SystemInfoSchema
    score: ScoreBreakdownResult
    all_checks: List[AuditCheckResult]
    users_module: UserAuditModuleResult
    updates_module: UpdateAuditModuleResult
    permissions_module: PermissionAuditModuleResult
    services_module: ServiceAuditModuleResult
    security_module: SecurityConfigModuleResult
