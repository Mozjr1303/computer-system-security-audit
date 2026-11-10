import {
  AuditHistoryItem,
  FullAuditResult,
  PermissionAuditModuleResult,
  ReportMetadataItem,
  SecurityConfigModuleResult,
  ServiceAuditModuleResult,
  SystemInfo,
  UpdateAuditModuleResult,
  UserAuditModuleResult,
} from '../types/audit'

const API_BASE = 'http://127.0.0.1:8000/api'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
    },
    ...options,
  })
  if (!res.ok) {
    let errDetail = `HTTP ${res.status}`
    try {
      const body = await res.json()
      if (body.detail) errDetail = body.detail
    } catch {
      // ignore json parse error
    }
    throw new Error(errDetail)
  }
  return res.json() as Promise<T>
}

export const api = {
  getSystemInfo: () => request<SystemInfo>('/system/info'),

  startAudit: () =>
    request<FullAuditResult>('/audit/start', {
      method: 'POST',
    }),

  getLatestAudit: () => request<FullAuditResult>('/audit/results/latest'),

  getAuditById: (auditId: string) =>
    request<FullAuditResult>(`/audit/results/${encodeURIComponent(auditId)}`),

  getUsersAudit: (refresh = false) =>
    request<UserAuditModuleResult>(`/audit/users?refresh=${refresh}`),

  getUpdatesAudit: (refresh = false) =>
    request<UpdateAuditModuleResult>(`/audit/updates?refresh=${refresh}`),

  getPermissionsAudit: (refresh = false) =>
    request<PermissionAuditModuleResult>(`/audit/permissions?refresh=${refresh}`),

  getServicesAudit: (refresh = false) =>
    request<ServiceAuditModuleResult>(`/audit/services?refresh=${refresh}`),

  getSecurityAudit: (refresh = false) =>
    request<SecurityConfigModuleResult>(`/audit/security?refresh=${refresh}`),

  getHistory: (limit = 50) =>
    request<{ items: AuditHistoryItem[] }>(`/history?limit=${limit}`),

  getReports: () => request<{ items: ReportMetadataItem[] }>('/reports'),

  generateReport: (auditId: string, format: 'pdf' | 'json' = 'pdf') =>
    request<ReportMetadataItem>(
      `/reports/${encodeURIComponent(auditId)}/generate?format=${format}`,
      {
        method: 'POST',
      },
    ),

  getReportDownloadUrl: (reportId: string) =>
    `${API_BASE}/reports/${encodeURIComponent(reportId)}/download`,
}
