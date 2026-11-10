import React from 'react'
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  HelpCircle,
  Info,
  ShieldAlert,
  Bug,
  Eye,
} from 'lucide-react'
import { CheckStatus, FindingType, SeverityLevel } from '../../types/audit'

export const StatusBadge: React.FC<{ status: CheckStatus }> = ({ status }) => {
  switch (status) {
    case 'PASS':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
          <CheckCircle2 className="w-3.5 h-3.5" /> PASS
        </span>
      )
    case 'FAIL':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30">
          <XCircle className="w-3.5 h-3.5" /> FAIL
        </span>
      )
    case 'WARNING':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">
          <AlertTriangle className="w-3.5 h-3.5" /> WARNING
        </span>
      )
    case 'NOT_ASSESSED':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-700/50 text-slate-300 border border-slate-600">
          <HelpCircle className="w-3.5 h-3.5" /> NOT ASSESSED
        </span>
      )
    default:
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/15 text-blue-400 border border-blue-500/30">
          <Info className="w-3.5 h-3.5" /> INFO
        </span>
      )
  }
}

export const SeverityBadge: React.FC<{ severity: SeverityLevel }> = ({ severity }) => {
  const styles: Record<SeverityLevel, string> = {
    Critical: 'bg-red-600/20 text-red-300 border-red-500/40',
    High: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
    Medium: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
    Low: 'bg-sky-500/20 text-sky-300 border-sky-500/40',
    Informational: 'bg-slate-700/40 text-slate-300 border-slate-600/50',
  }

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium border ${
        styles[severity] || styles.Informational
      }`}
    >
      {severity}
    </span>
  )
}

export const FindingTypeBadge: React.FC<{ type: FindingType }> = ({ type }) => {
  if (type === 'Confirmed Vulnerability') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-red-950/80 text-red-300 border border-red-800/60">
        <Bug className="w-3 h-3" /> Confirmed Vulnerability
      </span>
    )
  }
  if (type === 'Security Weakness') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-amber-950/80 text-amber-300 border border-amber-800/60">
        <ShieldAlert className="w-3 h-3" /> Security Weakness
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800/90 text-slate-400 border border-slate-700">
      <Eye className="w-3 h-3" /> Configuration Observation
    </span>
  )
}

export const ScoreGauge: React.FC<{ score: number; size?: number }> = ({
  score,
  size = 136,
}) => {
  const strokeWidth = 10
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const clamped = Math.max(0, Math.min(100, score))
  const offset = circumference - (clamped / 100) * circumference

  let color = '#10b981' // emerald
  if (clamped < 50) color = '#ef4444' // red
  else if (clamped < 80) color = '#f59e0b' // amber
  else if (clamped < 90) color = '#3b82f6' // blue

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke="#1e293b"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-extrabold text-white tracking-tight">{clamped}</span>
        <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">/ 100 PTS</span>
      </div>
    </div>
  )
}
