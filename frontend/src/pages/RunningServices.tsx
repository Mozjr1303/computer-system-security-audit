import React, { useState } from 'react'
import { ServerCog, Search, AlertTriangle } from 'lucide-react'
import { useAudit } from '../context/AuditContext'
import { SeverityBadge } from '../components/common/Badges'
import { FindingCard } from '../components/common/FindingCard'

export const RunningServices: React.FC = () => {
  const { currentAudit, runNewAudit, isScanning } = useAudit()
  const [search, setSearch] = useState('')
  const [filterMode, setFilterMode] = useState<
    'ALL' | 'RISKY' | 'RUNNING' | 'LOCALSYSTEM' | 'UNQUOTED'
  >('ALL')

  if (!currentAudit) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center">
        <p className="text-slate-300 mb-4">No Running Services audit data loaded yet.</p>
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

  const mod = currentAudit.services_module
  const catScore = currentAudit.score.categories.running_services

  const filteredServices = mod.services.filter((s) => {
    if (filterMode === 'RISKY' && !s.is_risky_service) return false
    if (filterMode === 'RUNNING' && s.state.toLowerCase() !== 'running') return false
    if (filterMode === 'LOCALSYSTEM' && !(s.is_elevated_system && s.state.toLowerCase() === 'running'))
      return false
    if (filterMode === 'UNQUOTED' && !s.has_unquoted_path_risk) return false

    if (search.trim()) {
      const q = search.toLowerCase()
      return (
        s.name.toLowerCase().includes(q) ||
        s.display_name.toLowerCase().includes(q) ||
        s.path_name.toLowerCase().includes(q)
      )
    }
    return true
  })

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="p-3.5 rounded-xl bg-blue-600/20 border border-blue-500/30 text-blue-400">
            <ServerCog className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Module E: Running Services Audit</h1>
            <p className="text-xs text-slate-400">
              Inspection of {mod.total_services} Windows services for CWE-428 unquoted binary paths, LocalSystem elevation, and legacy services
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

      {/* KPI Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 text-xs">
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <div className="text-slate-400">Total Services</div>
          <div className="text-2xl font-extrabold text-white mt-1">{mod.total_services}</div>
        </div>
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <div className="text-emerald-400">Running Services</div>
          <div className="text-2xl font-extrabold text-emerald-400 mt-1">
            {mod.running_services}
          </div>
        </div>
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <div className="text-slate-400">Stopped Services</div>
          <div className="text-2xl font-extrabold text-slate-300 mt-1">
            {mod.stopped_services}
          </div>
        </div>
        <div className="bg-slate-900/90 border border-amber-500/25 rounded-xl p-4">
          <div className="text-amber-400">Running as LocalSystem</div>
          <div className="text-2xl font-extrabold text-amber-400 mt-1">
            {mod.elevated_running_services}
          </div>
        </div>
        <div className="bg-slate-900/90 border border-red-500/25 rounded-xl p-4">
          <div className="text-red-400">Risky / Flagged Services</div>
          <div className="text-2xl font-extrabold text-red-400 mt-1">
            {mod.risky_services_count}
          </div>
        </div>
      </div>

      {/* Search & Filter Controls */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search service name, display name, or binary path..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          {(
            [
              ['ALL', `All (${mod.total_services})`],
              ['RISKY', `Flagged Risks (${mod.risky_services_count})`],
              ['UNQUOTED', 'Unquoted Path (CWE-428)'],
              ['RUNNING', `Running (${mod.running_services})`],
              ['LOCALSYSTEM', `LocalSystem (${mod.elevated_running_services})`],
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              onClick={() => setFilterMode(key)}
              className={`px-3 py-1.5 rounded-lg font-medium border transition cursor-pointer ${
                filterMode === key
                  ? 'bg-blue-600/20 text-blue-400 border-blue-500/40'
                  : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Services Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto max-h-[480px]">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="sticky top-0 bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3.5 px-4">Service Name</th>
                <th className="py-3.5 px-4">State / Startup</th>
                <th className="py-3.5 px-4">Logon Account</th>
                <th className="py-3.5 px-4">Binary PathName</th>
                <th className="py-3.5 px-4">Risk Level</th>
                <th className="py-3.5 px-4">Assessment & Remediation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {filteredServices.slice(0, 150).map((svc) => (
                <tr
                  key={svc.name}
                  className={
                    svc.is_risky_service
                      ? 'bg-red-950/20 hover:bg-red-950/30'
                      : 'hover:bg-slate-800/30'
                  }
                >
                  <td className="py-3 px-4">
                    <div className="font-semibold text-white">{svc.display_name}</div>
                    <div className="font-mono text-[11px] text-blue-400">
                      {svc.name} {svc.process_id > 0 ? `(PID: ${svc.process_id})` : ''}
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <span
                      className={`inline-block px-2 py-0.5 rounded font-semibold ${
                        svc.state.toLowerCase() === 'running'
                          ? 'bg-emerald-500/15 text-emerald-400'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {svc.state}
                    </span>
                    <div className="text-[11px] text-slate-500 mt-0.5">
                      Start: {svc.start_mode}
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-300">
                    {svc.start_name}
                    {svc.is_elevated_system && (
                      <div className="text-[10px] text-amber-400">Elevated SYSTEM</div>
                    )}
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-slate-300 max-w-xs break-all">
                    {svc.has_unquoted_path_risk && (
                      <div className="inline-flex items-center gap-1 text-red-400 font-sans font-bold mb-1">
                        <AlertTriangle className="w-3.5 h-3.5" /> Unquoted Path with Spaces!
                      </div>
                    )}
                    <div>{svc.path_name || 'N/A'}</div>
                  </td>
                  <td className="py-3 px-4">
                    <SeverityBadge severity={svc.risk_level} />
                  </td>
                  <td className="py-3 px-4 max-w-sm">
                    <div className={svc.is_risky_service ? 'text-red-300 font-medium' : 'text-slate-400'}>
                      {svc.risk_explanation}
                    </div>
                    {svc.is_risky_service && (
                      <div className="text-emerald-400 text-[11px] mt-1">
                        Rec: {svc.recommendation}
                      </div>
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
          Running Services Security Checks ({mod.checks.length})
        </h2>
        {mod.checks.map((chk) => (
          <FindingCard key={chk.check_id} check={chk} />
        ))}
      </div>
    </div>
  )
}
