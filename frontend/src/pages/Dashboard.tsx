import React from 'react'
import { useNavigate } from 'react-router-dom'
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ShieldAlert,
  Play,
  Cpu,
  HardDrive,
  Terminal,
  ArrowRight,
  Clock,
  Activity,
} from 'lucide-react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts'
import { useAudit } from '../context/AuditContext'
import { ScoreGauge, SeverityBadge, StatusBadge } from '../components/common/Badges'
import { FindingCard } from '../components/common/FindingCard'

export const Dashboard: React.FC = () => {
  const {
    systemInfo,
    currentAudit,
    history,
    isScanning,
    runNewAudit,
    loadAuditById,
  } = useAudit()
  const navigate = useNavigate()

  if (!currentAudit) {
    return (
      <div className="space-y-6">
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-8 text-center max-w-2xl mx-auto my-8 shadow-2xl">
          <div className="w-16 h-16 rounded-2xl bg-blue-600/20 border border-blue-500/40 text-blue-400 flex items-center justify-center mx-auto mb-4">
            <ShieldAlert className="w-8 h-8" />
          </div>
          <h1 className="text-2xl font-bold text-white mb-2">
            Ready to Audit {systemInfo?.hostname || 'Windows Host'}
          </h1>
          <p className="text-sm text-slate-400 mb-6 leading-relaxed">
            Perform a comprehensive, read-only security posture assessment across User Accounts,
            Windows Updates, File Permissions, Running Services, and Security Configurations.
          </p>
          <button
            onClick={runNewAudit}
            disabled={isScanning}
            className="inline-flex items-center gap-2.5 px-6 py-3 rounded-xl font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-600/25 transition cursor-pointer disabled:opacity-50"
          >
            <Play className="w-4 h-4 fill-current" />
            {isScanning ? 'Running Security Audit...' : 'Start First Security Audit'}
          </button>
        </div>
      </div>
    )
  }

  const { score, all_checks } = currentAudit
  const categoryList = Object.values(score.categories)

  const barData = categoryList.map((c) => ({
    name: c.category_label.replace(' Configurations', ' Config'),
    Earned: c.earned_points,
    Max: c.max_points,
    pct: c.percentage,
  }))

  const pieData = [
    { name: 'Passed', value: score.passed_checks, color: '#10b981' },
    { name: 'Failed', value: score.failed_checks, color: '#ef4444' },
    { name: 'Warnings', value: score.warning_checks, color: '#f59e0b' },
    { name: 'Not Assessed', value: score.not_assessed_checks, color: '#64748b' },
  ].filter((d) => d.value > 0)

  const priorityFindings = all_checks.filter(
    (c) => c.status === 'FAIL' || c.status === 'WARNING',
  )

  return (
    <div className="space-y-6">
      {/* Top Banner & Score Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-5 bg-slate-900/90 border border-slate-800 rounded-2xl p-6 flex flex-col sm:flex-row items-center gap-6 shadow-xl">
          <ScoreGauge score={score.overall_score} size={148} />
          <div className="space-y-2 text-center sm:text-left">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-semibold bg-blue-500/15 text-blue-300 border border-blue-500/30">
              Audit ID: {currentAudit.audit_id}
            </div>
            <h2 className="text-xl font-bold text-white">{score.risk_rating}</h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              {score.executive_summary}
            </p>
          </div>
        </div>

        {/* KPI Cards */}
        <div className="lg:col-span-7 grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Total Checks</span>
              <Activity className="w-4 h-4 text-blue-400" />
            </div>
            <div className="my-2">
              <div className="text-3xl font-extrabold text-white">{score.total_checks}</div>
              <div className="text-[11px] text-slate-400 mt-1">Across 5 core domains</div>
            </div>
          </div>

          <div className="bg-slate-900/90 border border-emerald-500/20 rounded-2xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-emerald-400">Passed Checks</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="my-2">
              <div className="text-3xl font-extrabold text-emerald-400">
                {score.passed_checks}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                {Math.round((score.passed_checks / score.total_checks) * 100)}% compliance rate
              </div>
            </div>
          </div>

          <div className="bg-slate-900/90 border border-red-500/25 rounded-2xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-red-400">Failed Checks</span>
              <XCircle className="w-4 h-4 text-red-400" />
            </div>
            <div className="my-2">
              <div className="text-3xl font-extrabold text-red-400">
                {score.failed_checks}
              </div>
              <div className="text-[11px] text-red-300/80 mt-1">
                {score.critical_findings_count} Critical • {score.high_findings_count} High
              </div>
            </div>
          </div>

          <div className="bg-slate-900/90 border border-amber-500/25 rounded-2xl p-5 flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-amber-400">Warnings / N.A.</span>
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            </div>
            <div className="my-2">
              <div className="text-3xl font-extrabold text-amber-400">
                {score.warning_checks}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                {score.not_assessed_checks} Not Assessed
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Visual Analytics Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-white">
                Security Category Score Breakdown
              </h3>
              <p className="text-xs text-slate-400">
                Earned points vs. maximum allocation per audit module (100 points total)
              </p>
            </div>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData} margin={{ top: 10, right: 20, left: 0, bottom: 5 }}>
                <XAxis dataKey="name" stroke="#94a3b8" fontSize={12} />
                <YAxis stroke="#94a3b8" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#1e293b',
                    borderRadius: '8px',
                    color: '#f8fafc',
                  }}
                />
                <Legend />
                <Bar dataKey="Earned" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                <Bar dataKey="Max" fill="#1e293b" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="lg:col-span-5 bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
          <div className="mb-4">
            <h3 className="text-base font-bold text-white">Check Status Distribution</h3>
            <p className="text-xs text-slate-400">
              Breakdown of all {score.total_checks} security checks executed on {currentAudit.system_info.hostname}
            </p>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {pieData.map((entry, idx) => (
                    <Cell key={idx} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#1e293b',
                    borderRadius: '8px',
                    color: '#f8fafc',
                  }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Category Progress Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        {categoryList.map((cat) => {
          const routeMap: Record<string, string> = {
            user_accounts: '/audit/users',
            system_updates: '/audit/updates',
            file_permissions: '/audit/permissions',
            running_services: '/audit/services',
            security_config: '/audit/security',
          }
          return (
            <div
              key={cat.category}
              onClick={() => navigate(routeMap[cat.category] || '/')}
              className="bg-slate-900/80 hover:bg-slate-900 border border-slate-800 hover:border-blue-500/40 rounded-xl p-4 cursor-pointer transition group"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-slate-300 group-hover:text-blue-400 transition">
                  {cat.category_label}
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-blue-400 transition" />
              </div>
              <div className="flex items-baseline justify-between mb-2">
                <span className="text-xl font-bold text-white">
                  {cat.earned_points}{' '}
                  <span className="text-xs font-normal text-slate-400">/ {cat.max_points} pts</span>
                </span>
                <span className="text-xs font-mono text-blue-400">{cat.percentage}%</span>
              </div>
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-500 rounded-full"
                  style={{ width: `${Math.min(100, cat.percentage)}%` }}
                />
              </div>
              <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2.5">
                <span className="text-emerald-400">{cat.passed_checks} Pass</span>
                <span className="text-red-400">{cat.failed_checks} Fail</span>
                <span className="text-amber-400">{cat.warning_checks} Warn</span>
              </div>
            </div>
          )
        })}
      </div>

      {/* Bottom Row: Actionable Findings & System Profile + History */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-bold text-white">
                Priority Security Findings ({priorityFindings.length})
              </h3>
              <p className="text-xs text-slate-400">
                Identified vulnerabilities and security weaknesses requiring remediation
              </p>
            </div>
          </div>

          {priorityFindings.length === 0 ? (
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 text-center text-slate-400">
              All assessed security checks passed without failures or warnings.
            </div>
          ) : (
            <div className="space-y-4">
              {priorityFindings.map((chk) => (
                <FindingCard key={chk.check_id} check={chk} />
              ))}
            </div>
          )}
        </div>

        <div className="lg:col-span-4 space-y-6">
          {/* Host System Profile */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-blue-400" /> Audited Computer Profile
            </h3>
            <div className="space-y-2.5 text-xs">
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <span className="text-slate-400">Hostname</span>
                <span className="font-mono font-semibold text-white">
                  {currentAudit.system_info.hostname}
                </span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <span className="text-slate-400">Operating System</span>
                <span className="text-slate-200 font-medium text-right">
                  {currentAudit.system_info.os_name}
                </span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <span className="text-slate-400">OS Version / Build</span>
                <span className="font-mono text-slate-200">
                  {currentAudit.system_info.os_version} (Build {currentAudit.system_info.os_build})
                </span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <span className="text-slate-400">Hardware Model</span>
                <span className="text-slate-200 text-right">
                  {currentAudit.system_info.manufacturer} {currentAudit.system_info.model}
                </span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <span className="text-slate-400">Processor</span>
                <span className="text-slate-200 text-right truncate max-w-[200px]">
                  {currentAudit.system_info.cpu_Model} ({currentAudit.system_info.cpu_cores} cores)
                </span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <span className="text-slate-400">Installed RAM</span>
                <span className="font-mono text-slate-200">
                  {currentAudit.system_info.ram_total_gb} GB
                </span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/80">
                <span className="text-slate-400">Domain / Workgroup</span>
                <span className="text-slate-200">
                  {currentAudit.system_info.domain_or_workgroup}
                </span>
              </div>
              <div className="flex justify-between py-1.5">
                <span className="text-slate-400">System Uptime</span>
                <span className="font-mono text-slate-200">
                  {currentAudit.system_info.uptime_hours} hours
                </span>
              </div>
            </div>
          </div>

          {/* Recent Audit History */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Clock className="w-4 h-4 text-blue-400" /> Recent Audit Sessions
              </h3>
              <button
                onClick={() => navigate('/history')}
                className="text-xs text-blue-400 hover:underline cursor-pointer"
              >
                View All
              </button>
            </div>
            <div className="space-y-2.5">
              {history.slice(0, 5).map((h) => (
                <div
                  key={h.audit_id}
                  onClick={() => loadAuditById(h.audit_id)}
                  className={`p-3 rounded-xl border text-xs cursor-pointer transition flex items-center justify-between ${
                    h.audit_id === currentAudit.audit_id
                      ? 'bg-blue-600/15 border-blue-500/40'
                      : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div>
                    <div className="font-mono font-semibold text-slate-200">{h.audit_id}</div>
                    <div className="text-slate-400 text-[11px]">
                      {new Date(h.completed_at).toLocaleString()}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-bold text-white">{h.overall_score}/100</div>
                    <div className="text-[11px] text-slate-400">
                      {h.passed_checks}P / {h.failed_checks}F / {h.warning_checks}W
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
