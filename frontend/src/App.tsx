import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { AuditProvider } from './context/AuditContext'
import { Sidebar } from './components/layout/Sidebar'
import { Header } from './components/layout/Header'
import { Dashboard } from './pages/Dashboard'
import { StartAudit } from './pages/StartAudit'
import { UserAccounts } from './pages/UserAccounts'
import { SystemUpdates } from './pages/SystemUpdates'
import { FilePermissions } from './pages/FilePermissions'
import { RunningServices } from './pages/RunningServices'
import { SecurityConfig } from './pages/SecurityConfig'
import { AuditReports } from './pages/AuditReports'
import { AuditHistory } from './pages/AuditHistory'
import { Settings } from './pages/Settings'

export default function App() {
  return (
    <BrowserRouter>
      <AuditProvider>
        <div className="min-h-screen bg-[#060b16] text-slate-100 flex">
          <Sidebar />
          <div className="flex-1 flex flex-col min-w-0">
            <Header />
            <main className="flex-1 p-6 overflow-y-auto">
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/audit/start" element={<StartAudit />} />
                <Route path="/audit/users" element={<UserAccounts />} />
                <Route path="/audit/updates" element={<SystemUpdates />} />
                <Route path="/audit/permissions" element={<FilePermissions />} />
                <Route path="/audit/services" element={<RunningServices />} />
                <Route path="/audit/security" element={<SecurityConfig />} />
                <Route path="/reports" element={<AuditReports />} />
                <Route path="/history" element={<AuditHistory />} />
                <Route path="/settings" element={<Settings />} />
              </Routes>
            </main>
          </div>
        </div>
      </AuditProvider>
    </BrowserRouter>
  )
}
