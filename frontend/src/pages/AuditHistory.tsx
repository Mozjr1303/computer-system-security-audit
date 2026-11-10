import React from 'react'
import { useNavigate } from 'react-router-dom'
import { History, Eye } from 'lucide-react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { useAudit } from '../context/AuditContext'

export const AuditHistory: React.FC = () => {
  const { history, currentAudit, loadAuditById } = useAudit()
  const navigate = useNavigate()

  const chartData = [...history]
    .reverse()
    .map((h) => ({
      time: new Date(h.completed_at).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
      }),
      Score: h.overall_score,
      audit_id: h.audit_id,
    }))

  const handleSelect = async (auditId: string) => {
    await loadAuditById(auditId)
    navigate('/')
  }

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3.5 rounded-xl bg-blue-600/20 border border-blue-500/30 text-blue-400">
            <History className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">SQLite Audit History & Score Trends</h1>
            <p className="text-xs text-slate-400">
              Historical record of all security posture scans executed and stored in SQLite
            </p>
          </div>
        </div>
      </div>

      {chartData.length > 0 && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
          <h2 className="text-base font-bold text-white mb-4">
            Historical Security Posture Score Trend
          </h2>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <XAxis dataKey="time" stroke="#94a3b8" fontSize={12} />
                <YAxis domain={[0, 100]} stroke="#94a3b8" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#1e293b',
                    borderRadius: '8px',
                    color: '#f8fafc',
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="Score"
                  stroke="#3b82f6"
                  strokeWidth={3}
                  dot={{ r: 5, fill: '#3b82f6' }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* History Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="p-5 border-b border-slate-800">
          <h2 className="text-base font-bold text-white">
            Stored Audit Sessions ({history.length})
          </h2>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                <th className="py-3.5 px-4">Audit ID</th>
                <th className="py-3.5 px-4">Completed Timestamp</th>
                <th className="py-3.5 px-4">Host & Context</th>
                <th className="py-3.5 px-4">Overall Score</th>
                <th className="py-3.5 px-4">Check Breakdown</th>
                <th className="py-3.5 px-4">Duration</th>
                <th className="py-3.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {history.map((h) => (
                <tr
                  key={h.audit_id}
                  className={
                    h.audit_id === currentAudit?.audit_id
                      ? 'bg-blue-950/20'
                      : 'hover:bg-slate-800/30'
                  }
                >
                  <td className="py-3.5 px-4 font-mono font-bold text-blue-400">
                    {h.audit_id}
                  </td>
                  <td className="py-3.5 px-4 text-slate-300">
                    {new Date(h.completed_at).toLocaleString()}
                  </td>
                  <td className="py-3.5 px-4 text-slate-300">
                    <div className="font-semibold">{h.hostname}</div>
                    <div className="text-[11px] text-slate-500">
                      User: {h.current_user} ({h.is_admin ? 'Admin' : 'Standard'})
                    </div>
                  </td>
                  <td className="py-3.5 px-4">
                    <span className="text-base font-extrabold text-white">
                      {h.overall_score}/100
                    </span>
                    <div className="text-[11px] text-slate-400">{h.risk_rating}</div>
                  </td>
                  <td className="py-3.5 px-4 space-x-2">
                    <span className="text-emerald-400 font-semibold">{h.passed_checks} Pass</span>
                    <span className="text-red-400 font-semibold">{h.failed_checks} Fail</span>
                    <span className="text-amber-400 font-semibold">{h.warning_checks} Warn</span>
                    <span className="text-slate-400">{h.not_assessed_checks} N/A</span>
                  </td>
                  <td className="py-3.5 px-4 font-mono text-slate-400">
                    {h.duration_seconds}s
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <button
                      onClick={() => handleSelect(h.audit_id)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-blue-600 text-slate-200 hover:text-white font-semibold transition cursor-pointer"
                    >
                      <Eye className="w-3.5 h-3.5" /> Load Snapshot
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
