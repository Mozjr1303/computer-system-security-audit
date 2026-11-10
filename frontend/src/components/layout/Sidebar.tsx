import React from 'react'
import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  PlayCircle,
  Users,
  RefreshCw,
  FolderLock,
  ServerCog,
  ShieldCheck,
  FileText,
  History,
  Settings,
  Shield,
} from 'lucide-react'
import { useAudit } from '../../context/AuditContext'

export const Sidebar: React.FC = () => {
  const { currentAudit } = useAudit()
  const cats = currentAudit?.score.categories

  const navItems = [
    { to: '/', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/audit/start', label: 'Start New Audit', icon: PlayCircle },
    {
      to: '/audit/users',
      label: 'User Accounts',
      icon: Users,
      badge: cats?.user_accounts
        ? `${cats.user_accounts.earned_points}/${cats.user_accounts.max_points}`
        : '20 pts',
    },
    {
      to: '/audit/updates',
      label: 'System Updates',
      icon: RefreshCw,
      badge: cats?.system_updates
        ? `${cats.system_updates.earned_points}/${cats.system_updates.max_points}`
        : '20 pts',
    },
    {
      to: '/audit/permissions',
      label: 'File Permissions',
      icon: FolderLock,
      badge: cats?.file_permissions
        ? `${cats.file_permissions.earned_points}/${cats.file_permissions.max_points}`
        : '20 pts',
    },
    {
      to: '/audit/services',
      label: 'Running Services',
      icon: ServerCog,
      badge: cats?.running_services
        ? `${cats.running_services.earned_points}/${cats.running_services.max_points}`
        : '15 pts',
    },
    {
      to: '/audit/security',
      label: 'Security Configuration',
      icon: ShieldCheck,
      badge: cats?.security_config
        ? `${cats.security_config.earned_points}/${cats.security_config.max_points}`
        : '25 pts',
    },
    { to: '/reports', label: 'Audit Reports', icon: FileText },
    { to: '/history', label: 'Audit History', icon: History },
    { to: '/settings', label: 'Settings', icon: Settings },
  ]

  return (
    <aside className="w-64 shrink-0 bg-[#080d1a] border-r border-slate-800/90 flex flex-col justify-between min-h-screen select-none">
      <div>
        <div className="p-5 border-b border-slate-800/90 flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-blue-600/20 border border-blue-500/40 text-blue-400 shadow-inner">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-base tracking-tight text-white">WinSecAudit</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
                v1.0
              </span>
            </div>
            <p className="text-xs text-slate-400">Windows Security Auditor</p>
          </div>
        </div>

        <div className="px-3 py-4">
          <p className="px-3 text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
            Security Posture Modules
          </p>
          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === '/'}
                  className={({ isActive }) =>
                    `flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                      isActive
                        ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30 shadow-sm'
                        : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900/80 border border-transparent'
                    }`
                  }
                >
                  <div className="flex items-center gap-3">
                    <Icon className="w-4 h-4 shrink-0" />
                    <span className="truncate">{item.label}</span>
                  </div>
                  {item.badge && (
                    <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                      {item.badge}
                    </span>
                  )}
                </NavLink>
              )
            })}
          </nav>
        </div>
      </div>

      <div className="p-4 m-3 rounded-xl bg-slate-900/70 border border-slate-800/90 text-xs space-y-1.5">
        <div className="flex items-center justify-between text-slate-300 font-semibold">
          <span>Read-Only Mode</span>
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
        </div>
        <p className="text-slate-400 leading-relaxed text-[11px]">
          Non-destructive local host auditing. Zero system modifications.
        </p>
      </div>
    </aside>
  )
}
