import React from 'react'
import { ShieldCheck, Terminal } from 'lucide-react'
import { useAudit } from '../context/AuditContext'
import { SeverityBadge, StatusBadge } from '../components/common/Badges'
import { FindingCard } from '../components/common/FindingCard'

export const SecurityConfig: React.FC = () => {
  const { currentAudit, runNewAudit, isScanning } = useAudit()

  if (!currentAudit) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center">
        <p className="text-slate-300 mb-4">No Security Configuration audit data loaded yet.</p>
        <button
          onClick={runNewAudit}
          disabled={isScanning}
          className="px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-semibold cursor-pointer"
        >
          {isScanning ? 'Scanning...' : 'Run Security Audit'}
        </button>
      </div>
    )
  }

  const mod = currentAudit.security_module
  const catScore = currentAudit.score.categories.security_config

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="p-3.5 rounded-xl bg-blue-600/20 border border-blue-500/30 text-blue-400">
            <ShieldCheck className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">
              Module F: Security Configuration Audit
            </h1>
            <p className="text-xs text-slate-400">
              Assessment of Windows Defender, Firewall Profiles, UAC, Remote Desktop, UEFI Secure Boot, BitLocker, and SMBv1
            </p>
          </div>
        </div>
        <div className="text-right">
          <div className="text-xs text-slate-400">Category Score</div>
          <div className="text-2xl font-extrabold text-white">
            {catScore?.earned_points}{' '}
            <span className="text-sm text-slate-400">/ {catScore?.max_points} pts</span>
          </div>
        </div>
      </div>

      {/* 9 Control Posture Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {mod.controls.map((ctrl) => (
          <div
            key={ctrl.control_id}
            className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between shadow-lg"
          >
            <div>
              <div className="flex items-center justify-between gap-2 mb-3">
                <span className="text-[11px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-slate-800 text-blue-400 border border-slate-700">
                  {ctrl.control_id} • {ctrl.domain}
                </span>
                <StatusBadge status={ctrl.status} />
              </div>

              <h3 className="text-base font-bold text-white mb-1">{ctrl.name}</h3>
              <div className="text-sm font-semibold text-blue-300 mb-3">{ctrl.state_label}</div>

              <div className="p-2.5 rounded-lg bg-slate-950/90 border border-slate-800/80 mb-3">
                <div className="flex items-center gap-1 text-[10px] text-slate-400 uppercase mb-1">
                  <Terminal className="w-3 h-3 text-blue-400" /> Telemetry Evidence
                </div>
                <p className="font-mono text-[11px] text-slate-300 break-words">
                  {ctrl.evidence}
                </p>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
              <SeverityBadge severity={ctrl.severity} />
              <span className="text-slate-400 truncate max-w-[200px]" title={ctrl.recommendation}>
                {ctrl.recommendation}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Detailed Check Breakdown */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold text-white">
          Detailed Security Configuration Findings ({mod.checks.length})
        </h2>
        {mod.checks.map((chk) => (
          <FindingCard key={chk.check_id} check={chk} />
        ))}
      </div>
    </div>
  )
}
