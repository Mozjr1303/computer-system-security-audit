export type CheckStatus = 'PASS' | 'FAIL' | 'WARNING' | 'INFO' | 'NOT_ASSESSED'

export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'

export type FindingType =
  | 'Security Weakness'
  | 'Confirmed Vulnerability'
  | 'Configuration Observation'

export type AuditCategory =
  | 'user_accounts'
  | 'system_updates'
  | 'file_permissions'
  | 'running_services'
  | 'security_config'

export interface SystemInfo {
  hostname: string
  os_name: string
  os_version: string
  os_build: string
  architecture: string
  manufacturer: string
  model: string
  domain_or_workgroup: string
  current_user: string
  is_admin: boolean
  powershell_version: string
  cpu_Model: string
  cpu_cores: number
  ram_total_gb: number
  boot_time: string
  uptime_hours: number
  collected_at: string
}

export interface AuditCheckResult {
  check_id: string
  category: AuditCategory
  title: string
  description: string
  status: CheckStatus
  severity: SeverityLevel
  finding_type: FindingType
  evidence: string
  explanation: string
  remediation: string
  metadata: Record<string, unknown>
}

export interface UserAccountDetail {
  username: string
  enabled: boolean
  account_type: string
  is_admin: boolean
  password_required: boolean
  password_never_expires: boolean
  last_logon: string | null
  sid: string | null
  description: string | null
  identified_risks: string[]
  recommendations: string[]
  risk_level: SeverityLevel
}

export interface PasswordPolicySummary {
  min_password_length: number | null
  max_password_age_days: string | null
  min_password_age_days: number | null
  lockout_threshold: string | null
  lockout_duration_mins: string | null
  lockout_observation_mins: string | null
  password_history_length: string | null
}

export interface UserAuditModuleResult {
  checks: AuditCheckResult[]
  accounts: UserAccountDetail[]
  password_policy: PasswordPolicySummary
  total_accounts: number
  enabled_accounts: number
  admin_accounts: number
}

export interface InstalledUpdateItem {
  hotfix_id: string
  description: string
  installed_by: string
  installed_on: string
  days_ago: number | null
}

export interface PendingUpdateItem {
  title: string
  kb_ids: string
  severity: string
  is_downloaded: boolean
}

export interface UpdateAuditModuleResult {
  checks: AuditCheckResult[]
  os_caption: string
  os_version: string
  os_build: string
  last_update_date: string | null
  days_since_last_update: number | null
  automatic_updates_enabled: boolean | null
  update_service_status: string
  installed_updates: InstalledUpdateItem[]
  pending_updates: PendingUpdateItem[]
  pending_scan_status: string
}

export interface PermissionEntryItem {
  path: string
  exists: boolean
  accessible: boolean
  owner: string
  identity: string
  rights: string
  access_control_type: string
  is_inherited: boolean
  is_risky: boolean
  security_concern: string
  recommended_action: string
  severity: SeverityLevel
}

export interface PermissionAuditModuleResult {
  checks: AuditCheckResult[]
  inspected_paths_count: number
  risky_permissions_count: number
  entries: PermissionEntryItem[]
}

export interface ServiceItemDetail {
  name: string
  display_name: string
  state: string
  start_mode: string
  start_name: string
  path_name: string
  process_id: number
  is_elevated_system: boolean
  has_unquoted_path_risk: boolean
  is_risky_service: boolean
  risk_level: SeverityLevel
  risk_explanation: string
  recommendation: string
}

export interface ServiceAuditModuleResult {
  checks: AuditCheckResult[]
  total_services: number
  running_services: number
  stopped_services: number
  elevated_running_services: number
  risky_services_count: number
  services: ServiceItemDetail[]
}

export interface SecurityControlItem {
  control_id: string
  domain: string
  name: string
  state_label: string
  status: CheckStatus
  severity: SeverityLevel
  evidence: string
  explanation: string
  recommendation: string
}

export interface SecurityConfigModuleResult {
  checks: AuditCheckResult[]
  controls: SecurityControlItem[]
}

export interface CategoryScoreSummary {
  category: AuditCategory
  category_label: string
  max_points: number
  earned_points: number
  percentage: number
  total_checks: number
  passed_checks: number
  failed_checks: number
  warning_checks: number
  info_checks: number
  not_assessed_checks: number
}

export interface ScoreBreakdownResult {
  overall_score: number
  max_score: number
  risk_rating: string
  executive_summary: string
  total_checks: number
  passed_checks: number
  failed_checks: number
  warning_checks: number
  info_checks: number
  not_assessed_checks: number
  critical_findings_count: number
  high_findings_count: number
  medium_findings_count: number
  low_findings_count: number
  categories: Record<string, CategoryScoreSummary>
  methodology_notes: string
}

export interface FullAuditResult {
  audit_id: string
  started_at: string
  completed_at: string
  duration_seconds: number
  system_info: SystemInfo
  score: ScoreBreakdownResult
  all_checks: AuditCheckResult[]
  users_module: UserAuditModuleResult
  updates_module: UpdateAuditModuleResult
  permissions_module: PermissionAuditModuleResult
  services_module: ServiceAuditModuleResult
  security_module: SecurityConfigModuleResult
}

export interface AuditHistoryItem {
  audit_id: string
  status: string
  started_at: string
  completed_at: string
  duration_seconds: number
  hostname: string
  os_name: string
  os_build: string
  current_user: string
  is_admin: boolean
  overall_score: number
  risk_rating: string
  total_checks: number
  passed_checks: number
  failed_checks: number
  warning_checks: number
  not_assessed_checks: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  categories: Record<
    string,
    {
      category_label: string
      earned_points: number
      max_points: number
      percentage: number
    }
  >
}

export interface ReportMetadataItem {
  report_id: string
  audit_id: string
  report_type: 'PDF' | 'JSON'
  title: string
  hostname: string
  overall_score: number
  file_name: string
  file_size_bytes: number
  created_at: string
  download_url?: string
}
