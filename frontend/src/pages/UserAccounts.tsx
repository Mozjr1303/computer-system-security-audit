import React from 'react'
import { Users, KeyRound, ShieldAlert, CheckCircle2, XCircle } from 'lucide-react'
import { useAudit } from '../context/AuditContext'
import { SeverityBadge } from '../components/common/Badges'
import { FindingCard } from '../components/common/FindingCard'

export const UserAccounts: React.FC = () => {
  const { currentAudit, runNewAudit, isScanning } = useAudit()

  if (!currentAudit) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center">
        <p className="text-slate-300 mb-4">No User Account audit data loaded yet.</p>
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

  const mod = currentAudit.users_module
  const catScore = currentAudit.score.categories.user_accounts
  const policy = mod.password_policy

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="p-3.5 rounded-xl bg-blue-600/20 border border-blue-500/30 text-blue-400">
            <Users className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Module B: User Account Audit</h1>
            <p className="text-xs text-slate-400">
              Inspection of local Windows user accounts, administrative groups, Guest status, and password policies
            </p>
          </div>
        </div>
        <div className="flex items-center gap-6">
          <div className="text-right">
            <div className="text-xs text-slate-400">Category Score</div>
            <div className="text-2xl font-extrabold text-white">
              {catScore?.earned_points} <span className="text-sm text-slate-400">/ {catScore?.max_points} pts</span>
            </div>
          </div>
        </div>
      </div>

      {/* Password & Lockout Policy Strip */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5">
        <h2 className="text-sm font-bold text-white flex items-center gap-2 mb-4">
          <KeyRound className="w-4 h-4 text-blue-400" /> Windows Password & Lockout Policy (net accounts)
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs">
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
            <div className="text-slate-400">Min Password Length</div>
            <div
              className={`text-base font-bold mt-1 ${
                (policy.min_password_length || 0) < 8 ? 'text-red-400' : 'text-emerald-400'
              }`}
            >
              {policy.min_password_length ?? 0} chars
            </div>
          </div>
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
            <div className="text-slate-400">Max Password Age</div>
            <div className="text-base font-bold text-white mt-1">
              {policy.max_password_age_days} days
            </div>
          </div>
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
            <div className="text-slate-400">Min Password Age</div>
            <div className="text-base font-bold text-white mt-1">
              {policy.min_password_age_days ?? 0} days
            </div>
          </div>
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
            <div className="text-slate-400">Lockout Threshold</div>
            <div className="text-base font-bold text-white mt-1">
              {policy.lockout_threshold}
            </div>
          </div>
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
            <div className="text-slate-400">Lockout Duration</div>
            <div className="text-base font-bold text-white mt-1">
              {policy.lockout_duration_mins} mins
            </div>
          </div>
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
            <div className="text-slate-400">Password History</div>
            <div className="text-base font-bold text-white mt-1">
              {policy.password_history_length}
            </div>
          </div>
        </div>
      </div>

      {/* Local User Accounts Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-white">
              Discovered Local User Accounts ({mod.total_accounts})
            </h2>
            <p className="text-xs text-slate-400">
              {mod.enabled_accounts} Enabled • {mod.admin_accounts} Active Administrator(s)
            </p>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-950/90 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                <th className="py-3.5 px-4">Username & SID</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4">Account Type</th>
                <th className="py-3.5 px-4">Admin Privileges</th>
                <th className="py-3.5 px-4">Password Policy</th>
                <th className="py-3.5 px-4">Risk Level</th>
                <th className="py-3.5 px-4">Identified Risks & Recommendations</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {mod.accounts.map((acc) => (
                <tr key={acc.username} className="hover:bg-slate-800/30 transition">
                  <td className="py-3.5 px-4">
                    <div className="font-semibold text-white text-sm">{acc.username}</div>
                    <div className="font-mono text-[11px] text-slate-500">{acc.sid}</div>
                  </td>
                  <td className="py-3.5 px-4">
                    {acc.enabled ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-medium">
                        <CheckCircle2 className="w-3 h-3" /> Enabled
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700 font-medium">
                        <XCircle className="w-3 h-3" /> Disabled
                      </span>
                    )}
                  </td>
                  <td className="py-3.5 px-4 text-slate-300 font-medium">{acc.account_type}</td>
                  <td className="py-3.5 px-4">
                    {acc.is_admin ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 font-semibold">
                        <ShieldAlert className="w-3 h-3" /> Administrator
                      </span>
                    ) : (
                      <span className="text-slate-400">Standard</span>
                    )}
                  </td>
                  <td className="py-3.5 px-4 space-y-1">
                    <div>
                      Pwd Required:{' '}
                      <span
                        className={
                          acc.password_required
                            ? 'text-emerald-400 font-semibold'
                            : 'text-red-400 font-bold'
                        }
                      >
                        {acc.password_required ? 'Yes' : 'NO'}
                      </span>
                    </div>
                    <div className="text-slate-400">
                      Never Expires: {acc.password_never_expires ? 'Yes' : 'No'}
                    </div>
                  </td>
                  <td className="py-3.5 px-4">
                    <SeverityBadge severity={acc.risk_level} />
                  </td>
                  <td className="py-3.5 px-4 max-w-md space-y-1">
                    {acc.identified_risks.length > 0 ? (
                      acc.identified_risks.map((r, i) => (
                        <div key={i} className="text-red-300 font-medium">
                          • {r}
                        </div>
                      ))
                    ) : (
                      <div className="text-emerald-400/90">• No account risks identified</div>
                    )}
                    {acc.recommendations.map((rec, i) => (
                      <div key={i} className="text-slate-400 text-[11px]">
                        Rec: {rec}
                      </div>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Security Check Findings */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold text-white">
          User Account Security Checks ({mod.checks.length})
        </h2>
        {mod.checks.map((chk) => (
          <FindingCard key={chk.check_id} check={chk} />
        ))}
      </div>
    </div>
  )
}
