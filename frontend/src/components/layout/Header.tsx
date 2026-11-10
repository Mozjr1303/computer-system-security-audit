import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Monitor,
  UserCheck,
  ShieldAlert,
  Play,
  FileDown,
  Loader2,
  Clock,
} from 'lucide-react'
import { useAudit } from '../../context/AuditContext'

export const Header: React.FC = () => {
  const {
    systemInfo,
    currentAudit,
    isScanning,
    runNewAudit,
    generateAndDownloadReport,
  } = useAudit()
  const [isExporting, setIsExporting] = useState(false)
  const navigate = useNavigate()

  const handleQuickScan = async () => {
    navigate('/audit/start')
    if (!isScanning) {
      await runNewAudit()
    }
  }

  const handleQuickPdf = async () => {
    if (!currentAudit) return
    setIsExporting(true)
    try {
      await generateAndDownloadReport(currentAudit.audit_id, 'pdf')
    } finally {
      setIsExporting(false)
    }
  }

  return (
    <header className="bg-[#080d1a]/90 backdrop-blur border-b border-slate-800/90 px-6 py-3.5 sticky top-0 z-20 flex flex-wrap items-center justify-between gap-4">
      <div className="flex flex-wrap items-center gap-3 text-xs">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-200">
          <Monitor className="w-4 h-4 text-blue-400" />
          <span className="font-semibold">{systemInfo?.hostname || 'Local Host'}</span>
          <span className="text-slate-500">•</span>
          <span className="text-slate-400">
            {systemInfo ? `${systemInfo.os_name} (Build ${systemInfo.os_build})` : 'Loading OS...'}
          </span>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">
          <UserCheck className="w-4 h-4 text-blue-400" />
          <span>{systemInfo?.current_user || 'User'}</span>
        </div>

        {systemInfo && (
          <div
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border font-medium ${
              systemInfo.is_admin
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
            }`}
            title={
              systemInfo.is_admin
                ? 'Running with full Administrator privileges'
                : 'Running in Standard User context; BitLocker check requires elevation'
            }
          >
            <ShieldAlert className="w-4 h-4" />
            <span>{systemInfo.is_admin ? 'Administrator Context' : 'Standard User Context'}</span>
          </div>
        )}

        {currentAudit && (
          <div className="hidden xl:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900/70 border border-slate-800/80 text-slate-400">
            <Clock className="w-3.5 h-3.5 text-slate-500" />
            <span>Last Scan: {new Date(currentAudit.completed_at).toLocaleString()}</span>
          </div>
        )}
      </div>

      <div className="flex items-center gap-2.5">
        {currentAudit && (
          <button
            onClick={handleQuickPdf}
            disabled={isExporting}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition cursor-pointer disabled:opacity-50"
          >
            {isExporting ? (
              <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
            ) : (
              <FileDown className="w-4 h-4 text-blue-400" />
            )}
            Download PDF Report
          </button>
        )}

        <button
          onClick={handleQuickScan}
          disabled={isScanning}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-600/20 transition cursor-pointer disabled:opacity-50"
        >
          {isScanning ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Scanning Host...
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-current" />
              Run Security Audit
            </>
          )}
        </button>
      </div>
    </header>
  )
}
