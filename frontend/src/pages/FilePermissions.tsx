import React, { useState } from 'react'
import { FolderLock, Filter } from 'lucide-react'
import { useAudit } from '../context/AuditContext'
import { SeverityBadge } from '../components/common/Badges'
import { FindingCard } from '../components/common/FindingCard'

export const FilePermissions: React.FC = () => {
  const { currentAudit, runNewAudit, isScanning } = useAudit()
  const [selectedPath, setSelectedPath] = useState<string>('ALL')
  const [riskyOnly, setRiskyOnly] = useState<boolean>(false)

  if (!currentAudit) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center">
        <p className="text-slate-300 mb-4">No File Permission audit data loaded yet.</p>
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

  const mod = currentAudit.permissions_module
  const catScore = currentAudit.score.categories.file_permissions

  const uniquePaths = Array.from(new Set(mod.entries.map((e) => e.path)))
  const filteredEntries = mod.entries.filter((e) => {
    if (selectedPath !== 'ALL' && e.path !== selectedPath) return false
    if (riskyOnly && !e.is_risky) return false
    return true
  })

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="p-3.5 rounded-xl bg-blue-600/20 border border-blue-500/30 text-blue-400">
            <FolderLock className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Module D: File & Permission Audit</h1>
            <p className="text-xs text-slate-400">
              NTFS Access Control List (ACL) inspection across {mod.inspected_paths_count} sensitive system paths ({mod.entries.length} ACEs analyzed)
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

      {/* Filter Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3 flex-wrap">
          <Filter className="w-4 h-4 text-blue-400" />
          <select
            value={selectedPath}
            onChange={(e) => setSelectedPath(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono"
          >
            <option value="ALL">All Audited Paths ({mod.entries.length} ACEs)</option>
            {uniquePaths.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </div>

        <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
          <input
            type="checkbox"
            checked={riskyOnly}
            onChange={(e) => setRiskyOnly(e.target.checked)}
            className="rounded border-slate-700 bg-slate-950 text-blue-600"
          />
          Show Risky Permissions Only ({mod.risky_permissions_count})
        </label>
      </div>

      {/* NTFS ACE Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto max-h-[460px]">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="sticky top-0 bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3.5 px-4">Target Path</th>
                <th className="py-3.5 px-4">Identity / Principal</th>
                <th className="py-3.5 px-4">FileSystemRights</th>
                <th className="py-3.5 px-4">Type / Inherited</th>
                <th className="py-3.5 px-4">Severity</th>
                <th className="py-3.5 px-4">Security Assessment & Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {filteredEntries.map((entry, idx) => (
                <tr
                  key={`${entry.path}-${entry.identity}-${idx}`}
                  className={
                    entry.is_risky ? 'bg-red-950/20 hover:bg-red-950/30' : 'hover:bg-slate-800/30'
                  }
                >
                  <td className="py-3 px-4 font-mono text-slate-200 max-w-xs break-all">
                    <div>{entry.path}</div>
                    <div className="text-[10px] text-slate-500">Owner: {entry.owner}</div>
                  </td>
                  <td className="py-3 px-4 font-mono text-blue-300 font-medium">
                    {entry.identity}
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-300 max-w-xs break-words">
                    {entry.rights}
                  </td>
                  <td className="py-3 px-4 text-slate-400">
                    <div>{entry.access_control_type}</div>
                    <div className="text-[10px]">
                      {entry.is_inherited ? 'Inherited' : 'Explicit ACE'}
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <SeverityBadge severity={entry.severity} />
                  </td>
                  <td className="py-3 px-4 max-w-sm">
                    <div className={entry.is_risky ? 'text-red-300 font-medium' : 'text-slate-400'}>
                      {entry.security_concern}
                    </div>
                    {entry.is_risky && (
                      <div className="text-emerald-400 text-[11px] mt-1">
                        Action: {entry.recommended_action}
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
          File & Directory Permission Checks ({mod.checks.length})
        </h2>
        {mod.checks.map((chk) => (
          <FindingCard key={chk.check_id} check={chk} />
        ))}
      </div>
    </div>
  )
}
