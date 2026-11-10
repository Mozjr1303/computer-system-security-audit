import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Play,
  CheckCircle2,
  Loader2,
  ShieldCheck,
  Users,
  RefreshCw,
  FolderLock,
  ServerCog,
  FileDown,
  LayoutDashboard,
} from 'lucide-react'
import { useAudit } from '../context/AuditContext'

const AUDIT_STAGES = [
  {
    id: 'users',
    title: 'Module B: Local User Accounts & Password Policy',
    desc: 'Inspecting local users, Administrators group, Guest status, and net accounts policies (20 pts)',
    icon: Users,
  },
  {
    id: 'updates',
    title: 'Module C: Windows System Updates & Patch Currency',
    desc: 'Inspecting OS build support, installed KB hotfixes, wuauserv/UsoSvc, and Automatic Updates (20 pts)',
    icon: RefreshCw,
  },
  {
    id: 'permissions',
    title: 'Module D: Critical NTFS File & Directory Permissions',
    desc: 'Inspecting ACLs on System32, hosts file, Program Files, Startup folder, and shared directories (20 pts)',
    icon: FolderLock,
  },
  {
    id: 'services',
    title: 'Module E: Running Windows Services & Privilege Escalation',
    desc: 'Scanning 280+ Windows services for CWE-428 unquoted binary paths, LocalSystem risks, and legacy daemons (15 pts)',
    icon: ServerCog,
  },
  {
    id: 'security',
    title: 'Module F: Windows Security Configurations',
    desc: 'Auditing Windows Defender, Firewall profiles, UAC, RDP/NLA, UEFI Secure Boot, BitLocker, and SMBv1 (25 pts)',
    icon: ShieldCheck,
  },
]

export const StartAudit: React.FC = () => {
  const {
    systemInfo,
    currentAudit,
    isScanning,
    runNewAudit,
    generateAndDownloadReport,
  } = useAudit()
  const [activeStage, setActiveStage] = useState<number>(-1)
  const navigate = useNavigate()

  useEffect(() => {
    if (!isScanning) {
      setActiveStage(-1)
      return
    }
    setActiveStage(0)
    const interval = setInterval(() => {
      setActiveStage((prev) => (prev < AUDIT_STAGES.length - 1 ? prev + 1 : prev))
    }, 4200)
    return () => clearInterval(interval)
  }, [isScanning])

  const handleStart = async () => {
    await runNewAudit()
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-8 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-slate-800">
          <div>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-blue-500/15 text-blue-400 border border-blue-500/30 mb-2">
              Read-Only Local Host Assessment
            </span>
            <h1 className="text-2xl font-bold text-white">
              Windows Security Posture Scanner
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Target Host: <strong className="text-slate-200">{systemInfo?.hostname}</strong> •{' '}
              {systemInfo?.os_name} (Build {systemInfo?.os_build})
            </p>
          </div>

          <button
            onClick={handleStart}
            disabled={isScanning}
            className="inline-flex items-center justify-center gap-2.5 px-6 py-3.5 rounded-xl font-bold text-sm bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-600/25 transition cursor-pointer disabled:opacity-60 shrink-0"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Executing Live Checks...
              </>
            ) : (
              <>
                <Play className="w-5 h-5 fill-current" />
                Start New Security Audit
              </>
            )}
          </button>
        </div>

        {/* 5-Stage Pipeline */}
        <div className="mt-6 space-y-3">
          {AUDIT_STAGES.map((stage, idx) => {
            const Icon = stage.icon
            const isCompleted = !isScanning && currentAudit !== null
            const isCurrent = isScanning && idx === activeStage
            const isPassedStage = isScanning && idx < activeStage

            return (
              <div
                key={stage.id}
                className={`p-4 rounded-xl border transition flex items-center justify-between gap-4 ${
                  isCurrent
                    ? 'bg-blue-950/40 border-blue-500/50'
                    : isPassedStage || isCompleted
                      ? 'bg-slate-950/60 border-emerald-500/30'
                      : 'bg-slate-950/40 border-slate-800/80'
                }`}
              >
                <div className="flex items-center gap-4">
                  <div
                    className={`p-2.5 rounded-lg border ${
                      isCurrent
                        ? 'bg-blue-600/20 border-blue-500/40 text-blue-400'
                        : isPassedStage || isCompleted
                          ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400'
                          : 'bg-slate-900 border-slate-800 text-slate-500'
                    }`}
                  >
                    <Icon className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-white">{stage.title}</h3>
                    <p className="text-xs text-slate-400">{stage.desc}</p>
                  </div>
                </div>

                <div className="shrink-0">
                  {isCurrent ? (
                    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-400">
                      <Loader2 className="w-4 h-4 animate-spin" /> Auditing...
                    </span>
                  ) : isPassedStage || isCompleted ? (
                    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
                      <CheckCircle2 className="w-4 h-4" /> Verified
                    </span>
                  ) : (
                    <span className="text-xs text-slate-500 font-medium">Ready</span>
                  )}
                </div>
              </div>
            )
          })}
        </div>

        {/* Post-Scan Summary Banner */}
        {!isScanning && currentAudit && (
          <div className="mt-6 p-5 rounded-xl bg-emerald-950/20 border border-emerald-500/30 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div>
              <div className="text-xs font-mono text-emerald-400">
                COMPLETED IN {currentAudit.duration_seconds} SECONDS • {currentAudit.audit_id}
              </div>
              <div className="text-lg font-bold text-white mt-0.5">
                Overall Security Score: {currentAudit.score.overall_score} / 100 (
                {currentAudit.score.risk_rating})
              </div>
              <div className="text-xs text-slate-400 mt-0.5">
                {currentAudit.score.passed_checks} Passed • {currentAudit.score.failed_checks} Failed •{' '}
                {currentAudit.score.warning_checks} Warnings •{' '}
                {currentAudit.score.not_assessed_checks} Not Assessed
              </div>
            </div>

            <div className="flex items-center gap-3 shrink-0">
              <button
                onClick={() => generateAndDownloadReport(currentAudit.audit_id, 'pdf')}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white border border-slate-700 transition cursor-pointer"
              >
                <FileDown className="w-4 h-4 text-blue-400" />
                Download PDF Report
              </button>
              <button
                onClick={() => navigate('/')}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition cursor-pointer"
              >
                <LayoutDashboard className="w-4 h-4" />
                View Dashboard
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
