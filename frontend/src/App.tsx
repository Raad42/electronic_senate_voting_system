import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import { AuditPage } from './pages/AuditPage'
import { BallotPage } from './pages/BallotPage'
import { HomePage } from './pages/HomePage'
import { NotFoundPage } from './pages/NotFoundPage'
import { OfficialDashboardPage } from './pages/OfficialDashboardPage'
import { OfficialLoginPage } from './pages/OfficialLoginPage'
import { RecountPage } from './pages/RecountPage'
import { ResiliencePage } from './pages/ResiliencePage'

export default function App() {
  // Keep all route definitions inside the shared application shell.
  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/voter/ballot" element={<BallotPage />} />
        <Route path="/official" element={<OfficialDashboardPage />} />
        <Route path="/official/login" element={<OfficialLoginPage />} />
        <Route path="/official/recount" element={<RecountPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/resilience" element={<ResiliencePage />} />
        <Route path="/login" element={<Navigate to="/official/login" replace />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </AppShell>
  )
}
