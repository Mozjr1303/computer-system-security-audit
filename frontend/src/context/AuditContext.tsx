import React, { createContext, useContext, useEffect, useState, useCallback } from 'react'
import { api } from '../api/client'
import {
  AuditHistoryItem,
  FullAuditResult,
  ReportMetadataItem,
  SystemInfo,
} from '../types/audit'

interface AuditContextValue {
  systemInfo: SystemInfo | null
  currentAudit: FullAuditResult | null
  history: AuditHistoryItem[]
  reports: ReportMetadataItem[]
  isScanning: boolean
  isLoadingInitial: boolean
  error: string | null
  runNewAudit: () => Promise<FullAuditResult | null>
  loadAuditById: (auditId: string) => Promise<void>
  refreshHistoryAndReports: () => Promise<void>
  generateAndDownloadReport: (auditId: string, format: 'pdf' | 'json') => Promise<void>
}

const AuditContext = createContext<AuditContextValue | undefined>(undefined)

export const AuditProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null)
  const [currentAudit, setCurrentAudit] = useState<FullAuditResult | null>(null)
  const [history, setHistory] = useState<AuditHistoryItem[]>([])
  const [reports, setReports] = useState<ReportMetadataItem[]>([])
  const [isScanning, setIsScanning] = useState(false)
  const [isLoadingInitial, setIsLoadingInitial] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const refreshHistoryAndReports = useCallback(async () => {
    try {
      const [histRes, repRes] = await Promise.all([
        api.getHistory(),
        api.getReports(),
      ])
      setHistory(histRes.items)
      setReports(repRes.items)
    } catch (err) {
      console.error('Failed to load history/reports:', err)
    }
  }, [])

  useEffect(() => {
    let mounted = true
    async function bootstrap() {
      setIsLoadingInitial(true)
      try {
        const sys = await api.getSystemInfo()
        if (mounted) setSystemInfo(sys)
      } catch (err: unknown) {
        if (mounted) setError(err instanceof Error ? err.message : 'Backend connection failed')
      }

      try {
        const latest = await api.getLatestAudit()
        if (mounted) {
          setCurrentAudit(latest)
          setSystemInfo(latest.system_info)
        }
      } catch {
        // No audit run yet, which is fine
      }

      await refreshHistoryAndReports()
      if (mounted) setIsLoadingInitial(false)
    }
    bootstrap()
    return () => {
      mounted = false
    }
  }, [refreshHistoryAndReports])

  const runNewAudit = async (): Promise<FullAuditResult | null> => {
    setIsScanning(true)
    setError(null)
    try {
      const result = await api.startAudit()
      setCurrentAudit(result)
      setSystemInfo(result.system_info)
      await refreshHistoryAndReports()
      return result
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Audit scan failed'
      setError(msg)
      return null
    } finally {
      setIsScanning(false)
    }
  }

  const loadAuditById = async (auditId: string) => {
    setError(null)
    try {
      const result = await api.getAuditById(auditId)
      setCurrentAudit(result)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load audit session')
    }
  }

  const generateAndDownloadReport = async (auditId: string, format: 'pdf' | 'json') => {
    setError(null)
    try {
      const meta = await api.generateReport(auditId, format)
      await refreshHistoryAndReports()
      const url = api.getReportDownloadUrl(meta.report_id)
      window.open(url, '_blank')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to generate report')
      throw err
    }
  }

  return (
    <AuditContext.Provider
      value={{
        systemInfo,
        currentAudit,
        history,
        reports,
        isScanning,
        isLoadingInitial,
        error,
        runNewAudit,
        loadAuditById,
        refreshHistoryAndReports,
        generateAndDownloadReport,
      }}
    >
      {children}
    </AuditContext.Provider>
  )
}

export function useAudit() {
  const ctx = useContext(AuditContext)
  if (!ctx) {
    throw new Error('useAudit must be used within an AuditProvider')
  }
  return ctx
}
