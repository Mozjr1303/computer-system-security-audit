import React from 'react'
import { Terminal, Info, Wrench } from 'lucide-react'
import { AuditCheckResult } from '../../types/audit'
import { FindingTypeBadge, SeverityBadge, StatusBadge } from './Badges'

export const FindingCard: React.FC<{ check: AuditCheckResult }> = ({ check }) => {
  const borderAccent =
    check.status === 'FAIL'
      ? 'border-l-4 border-l-red-500 border-slate-800'
      : check.status === 'WARNING'
        ? 'border-l-4 border-l-amber-500 border-slate-800'
        : check.status === 'NOT_ASSESSED'
          ? 'border-l-4 border-l-slate-600 border-slate-800'
          : 'border-l-4 border-l-emerald-500 border-slate-800/90'

  return (
    <div className={`bg-slate-900/80 border ${borderAccent} rounded-xl p-5 shadow-lg transition hover:border-slate-700`}>
      <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-2.5">
          <span className="px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/30 text-blue-400 font-mono text-xs font-bold">
            {check.check_id}
          </span>
          <h3 className="text-base font-semibold text-white">{check.title}</h3>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <FindingTypeBadge type={check.finding_type} />
          <SeverityBadge severity={check.severity} />
          <StatusBadge status={check.status} />
        </div>
      </div>

      <p className="text-sm text-slate-400 mb-4">{check.description}</p>

      <div className="space-y-3 text-sm">
        <div className="bg-slate-950/90 border border-slate-800/90 rounded-lg p-3">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
            <Terminal className="w-3.5 h-3.5 text-blue-400" /> Collected Host Evidence
          </div>
          <p className="font-mono text-xs text-slate-200 break-words leading-relaxed">
            {check.evidence || 'No evidence output recorded.'}
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="bg-slate-950/50 border border-slate-800/70 rounded-lg p-3">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-amber-400/90 uppercase tracking-wider mb-1">
              <Info className="w-3.5 h-3.5" /> Security Impact & Why It Matters
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">{check.explanation}</p>
          </div>

          <div className="bg-slate-950/50 border border-slate-800/70 rounded-lg p-3">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400/90 uppercase tracking-wider mb-1">
              <Wrench className="w-3.5 h-3.5" /> Recommended Remediation
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">{check.remediation}</p>
          </div>
        </div>
      </div>
    </div>
  )
}
