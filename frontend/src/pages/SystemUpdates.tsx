import React from 'react'
import { RefreshCw, Calendar, CheckCircle2, Server } from 'lucide-react'
import { useAudit } from '../context/AuditContext'
import { FindingCard } from '../components/common/FindingCard'

export const SystemUpdates: React.FC = () => {
  const { currentAudit, runNewAudit, isScanning } = useAudit()

  if (!currentAudit) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center">
        <p className="text-slate-300 mb-4">No System Update audit data loaded yet.</p>
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

  const mod = currentAudit.updates_module
  const catScore = currentAudit.score.categories.system_updates

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="p-3.5 rounded-xl bg-blue-600/20 border border-blue-500/30 text-blue-400">
            <RefreshCw className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Module C: System Update Audit</h1>
            <p className="text-xs text-slate-400">
              Examination of Windows servicing build, installed KB hotfixes, update services, and Automatic Update posture
            </p>
          </div>
        </div>
        <div className="text-right">
          <div className="text-xs text-slate-400">Category Score</div>
          <div className="text-2xl font-extrabold text-white">
            {catScore?.earned_points} <span className="text-sm text-slate-400">/ {catScore?.max_points} pts</span>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400">OS Build & Version</div>
          <div className="text-base font-bold text-white mt-1">{mod.os_caption}</div>
          <div className="text-xs font-mono text-blue-400 mt-0.5">
            Version {mod.os_version} • Build {mod.os_build}
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400 flex items-center gap-1.5">
            <Calendar className="w-3.5 h-3.5 text-blue-400" /> Latest Installed Update
          </div>
          <div className="text-base font-bold text-white mt-1">
            {mod.last_update_date || 'Unknown'}
          </div>
          <div className="text-xs text-emerald-400 mt-0.5">
            {mod.days_since_last_update !== null
              ? `${mod.days_since_last_update} days ago`
              : 'No date metadata'}
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> Automatic Updates
          </div>
          <div className="text-base font-bold text-white mt-1">
            {mod.automatic_updates_enabled ? 'Enabled & Active' : 'Disabled'}
          </div>
          <div className="text-xs text-slate-400 mt-0.5">
            {mod.installed_updates.length} Installed Hotfixes
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <div className="text-xs text-slate-400 flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-blue-400" /> Update Daemons
          </div>
          <div className="text-xs font-mono text-slate-200 mt-1.5 leading-relaxed">
            {mod.update_service_status}
          </div>
        </div>
      </div>

      {/* Installed Hotfixes Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="p-5 border-b border-slate-800">
          <h2 className="text-base font-bold text-white">
            Installed Windows Hotfixes & Security Updates ({mod.installed_updates.length})
          </h2>
          <p className="text-xs text-slate-400">
            Retrieved via PowerShell Get-HotFix on {currentAudit.system_info.hostname}
          </p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-950/90 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                <th className="py-3.5 px-4">HotFix ID (KB)</th>
                <th className="py-3.5 px-4">Classification / Description</th>
                <th className="py-3.5 px-4">Installed By</th>
                <th className="py-3.5 px-4">Installed On</th>
                <th className="py-3.5 px-4">Recency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {mod.installed_updates.map((u) => (
                <tr key={u.hotfix_id} className="hover:bg-slate-800/30 transition">
                  <td className="py-3.5 px-4 font-mono font-bold text-blue-400 text-sm">
                    {u.hotfix_id}
                  </td>
                  <td className="py-3.5 px-4 text-slate-200 font-medium">{u.description}</td>
                  <td className="py-3.5 px-4 font-mono text-slate-400">{u.installed_by}</td>
                  <td className="py-3.5 px-4 font-mono text-slate-300">{u.installed_on}</td>
                  <td className="py-3.5 px-4">
                    {u.days_ago !== null ? (
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                        {u.days_ago} days ago
                      </span>
                    ) : (
                      <span className="text-slate-500">N/A</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Checks */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold text-white">
          System Update Security Checks ({mod.checks.length})
        </h2>
        {mod.checks.map((chk) => (
          <FindingCard key={chk.check_id} check={chk} />
        ))}
      </div>
    </div>
  )
}
