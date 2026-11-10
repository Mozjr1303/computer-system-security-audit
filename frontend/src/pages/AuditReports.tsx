import React, { useState } from 'react'
import { FileText, FileDown, FileJson, Loader2, Download } from 'lucide-react'
import { useAudit } from '../context/AuditContext'
import { api } from '../api/client'

export const AuditReports: React.FC = () => {
  const {
    currentAudit,
    history,
    reports,
    generateAndDownloadReport,
  } = useAudit()
  const [selectedAuditId, setSelectedAuditId] = useState<string>(
    currentAudit?.audit_id || (history[0]?.audit_id ?? ''),
  )
  const [busyFormat, setBusyFormat] = useState<'pdf' | 'json' | null>(null)

  const activeId = selectedAuditId || currentAudit?.audit_id || ''

  const handleGenerate = async (format: 'pdf' | 'json') => {
    if (!activeId) return
    setBusyFormat(format)
    try {
      await generateAndDownloadReport(activeId, format)
    } finally {
      setBusyFormat(null)
    }
  }

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="p-3.5 rounded-xl bg-blue-600/20 border border-blue-500/30 text-blue-400">
            <FileText className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">
              Security Audit Deliverable Generator
            </h1>
            <p className="text-xs text-slate-400">
              Generate comprehensive PDF Security Audit Reports (ReportLab) and machine-readable JSON exports
            </p>
          </div>
        </div>
      </div>

      {/* Report Action Card */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 space-y-5 shadow-xl">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
          <div className="md:col-span-6">
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Select Completed Audit Session
            </label>
            <select
              value={activeId}
              onChange={(e) => setSelectedAuditId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-sm text-white font-mono"
            >
              {history.map((h) => (
                <option key={h.audit_id} value={h.audit_id}>
                  {h.audit_id} — {h.hostname} — Score: {h.overall_score}/100 (
                  {new Date(h.completed_at).toLocaleString()})
                </option>
              ))}
            </select>
          </div>

          <div className="md:col-span-6 flex flex-wrap gap-3">
            <button
              onClick={() => handleGenerate('pdf')}
              disabled={!activeId || busyFormat !== null}
              className="flex-1 inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl text-sm font-bold bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-600/25 transition cursor-pointer disabled:opacity-50"
            >
              {busyFormat === 'pdf' ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <FileDown className="w-4 h-4" />
              )}
              Generate & Download PDF Report
            </button>

            <button
              onClick={() => handleGenerate('json')}
              disabled={!activeId || busyFormat !== null}
              className="flex-1 inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl text-sm font-bold bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition cursor-pointer disabled:opacity-50"
            >
              {busyFormat === 'json' ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <FileJson className="w-4 h-4 text-emerald-400" />
              )}
              Export JSON Data
            </button>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 text-xs text-slate-400 leading-relaxed">
          <strong className="text-slate-200">Included in Official PDF Deliverable:</strong> 1. Project Title & Cover Header • 2. Target Computer Information • 3. OS & Build Details • 4. Audit Timestamps • 5. Executive Summary • 6. Overall Security Score & Category Breakdown Table • 7. User Account Findings • 8. System Update Findings • 9. File Permission Findings • 10. Running Services Findings • 11. Security Configuration Findings • 12. Identified Vulnerabilities & Weaknesses • 13. Recommended Remediation Roadmap • 14. Final Security Assessment.
        </div>
      </div>

      {/* Stored Reports Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="p-5 border-b border-slate-800">
          <h2 className="text-base font-bold text-white">
            Generated Audit Reports Archive ({reports.length})
          </h2>
        </div>

        {reports.length === 0 ? (
          <div className="p-8 text-center text-sm text-slate-400">
            No reports generated yet. Click &ldquo;Generate & Download PDF Report&rdquo; above to create your first deliverable.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                  <th className="py-3.5 px-4">Report ID</th>
                  <th className="py-3.5 px-4">Audit Session</th>
                  <th className="py-3.5 px-4">Format</th>
                  <th className="py-3.5 px-4">Host & Score</th>
                  <th className="py-3.5 px-4">File Name & Size</th>
                  <th className="py-3.5 px-4">Generated At</th>
                  <th className="py-3.5 px-4 text-right">Download</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {reports.map((r) => (
                  <tr key={r.report_id} className="hover:bg-slate-800/30 transition">
                    <td className="py-3.5 px-4 font-mono font-bold text-blue-400">
                      {r.report_id}
                    </td>
                    <td className="py-3.5 px-4 font-mono text-slate-300">{r.audit_id}</td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`px-2 py-0.5 rounded font-bold ${
                          r.report_type === 'PDF'
                            ? 'bg-red-500/15 text-red-300 border border-red-500/30'
                            : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                        }`}
                      >
                        {r.report_type}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-200">
                      {r.hostname} ({r.overall_score}/100)
                    </td>
                    <td className="py-3.5 px-4 font-mono text-slate-400">
                      {r.file_name} ({(r.file_size_bytes / 1024).toFixed(1)} KB)
                    </td>
                    <td className="py-3.5 px-4 text-slate-400">
                      {new Date(r.created_at).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <a
                        href={api.getReportDownloadUrl(r.report_id)}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 font-semibold transition"
                      >
                        <Download className="w-3.5 h-3.5" /> Download
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
