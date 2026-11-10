import React from 'react'
import { Settings as SettingsIcon, Shield, Scale, Lock } from 'lucide-react'

export const Settings: React.FC = () => {
  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 flex items-center gap-4">
        <div className="p-3.5 rounded-xl bg-blue-600/20 border border-blue-500/30 text-blue-400">
          <SettingsIcon className="w-7 h-7" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-white">
            Scoring Methodology & Security Architecture
          </h1>
          <p className="text-xs text-slate-400">
            Transparent documentation of the 100-point scoring algorithm, finding classifications, and read-only safety controls
          </p>
        </div>
      </div>

      {/* Scoring Allocation */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Scale className="w-4 h-4 text-blue-400" /> Transparent 100-Point Security Scoring Model
        </h2>
        <p className="text-xs text-slate-300 leading-relaxed">
          WinSecAudit calculates the overall security posture score out of 100 points across five core Windows security domains. Checks that return <code className="text-blue-300">NOT_ASSESSED</code> (for example, when a check requires Administrator elevation) are excluded from the category denominator so unavailable telemetry never artificially inflates or penalizes the host score.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-5 gap-3 text-xs">
          {[
            ['User Accounts', '20 Points', '7 Checks'],
            ['System Updates', '20 Points', '5 Checks'],
            ['File Permissions', '20 Points', '5 Checks'],
            ['Running Services', '15 Points', '5 Checks'],
            ['Security Config', '25 Points', '9 Checks'],
          ].map(([title, pts, chks]) => (
            <div key={title} className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
              <div className="text-slate-400">{title}</div>
              <div className="text-lg font-extrabold text-blue-400 mt-1">{pts}</div>
              <div className="text-[11px] text-slate-500">{chks}</div>
            </div>
          ))}
        </div>

        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs space-y-2">
          <div className="font-semibold text-white">Severity Weights & Status Multipliers:</div>
          <div className="text-slate-400">
            • <strong className="text-red-400">Critical:</strong> weight 10.0 |{' '}
            <strong className="text-orange-400">High:</strong> weight 6.0 |{' '}
            <strong className="text-amber-400">Medium:</strong> weight 3.0 |{' '}
            <strong className="text-sky-400">Low:</strong> weight 1.0 |{' '}
            <strong className="text-slate-400">Informational:</strong> weight 0.0
          </div>
          <div className="text-slate-400">
            • <strong className="text-emerald-400">PASS:</strong> awards 100% of check weight |{' '}
            <strong className="text-amber-400">WARNING:</strong> awards 50% of check weight |{' '}
            <strong className="text-red-400">FAIL:</strong> awards 0% of check weight.
          </div>
        </div>
      </div>

      {/* Finding Taxonomy */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 space-y-4">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Shield className="w-4 h-4 text-blue-400" /> Finding Classification Taxonomy
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-950 border border-red-900/50 space-y-1.5">
            <div className="font-bold text-red-400">1. Confirmed Vulnerability</div>
            <p className="text-slate-400 leading-relaxed">
              A directly exploitable security flaw verified on the host, such as an enabled user account with <code className="text-slate-200">PasswordRequired=False</code> or an unquoted service binary path containing spaces (<code className="text-slate-200">CWE-428</code>).
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-950 border border-amber-900/50 space-y-1.5">
            <div className="font-bold text-amber-400">2. Security Weakness</div>
            <p className="text-slate-400 leading-relaxed">
              A suboptimal security policy or missing defense-in-depth control that increases risk, such as a minimum password length of 0 or disabled Tamper Protection.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
            <div className="font-bold text-blue-400">3. Configuration Observation</div>
            <p className="text-slate-400 leading-relaxed">
              Verified baseline telemetry or compliant security controls recorded as audit evidence (e.g., Windows Firewall enabled across Domain, Private, and Public profiles).
            </p>
          </div>
        </div>
      </div>

      {/* Security & Read-Only Guarantees */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 space-y-3 text-xs">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Lock className="w-4 h-4 text-emerald-400" /> Application Security & Read-Only Guarantees
        </h2>
        <ul className="space-y-2 text-slate-300 list-disc list-inside leading-relaxed">
          <li>
            <strong>Zero Password Exposure:</strong> Never queries, extracts, or stores user passwords or NTLM hashes.
          </li>
          <li>
            <strong>No Arbitrary Command Execution:</strong> Frontend requests never pass shell arguments; the backend executes strictly predefined PowerShell script blocks with <code className="text-blue-300">shell=False</code>.
          </li>
          <li>
            <strong>Forbidden Verb Guard:</strong> Static enforcement in <code className="text-blue-300">powershell.py</code> blocks mutating cmdlets (<code className="text-slate-400">Stop-Service, Set-Service, Set-Acl, Disable-LocalUser, Remove-Item</code>).
          </li>
          <li>
            <strong>Localhost Loopback Isolation:</strong> FastAPI middleware restricts all API access strictly to <code className="text-blue-300">127.0.0.1</code> / <code className="text-blue-300">::1</code>.
          </li>
        </ul>
      </div>
    </div>
  )
}
