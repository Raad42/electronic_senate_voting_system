import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import { AuditPage } from './pages/AuditPage'
import { BallotPage } from './pages/BallotPage'
import { HomePage } from './pages/HomePage'
import { NotFoundPage } from './pages/NotFoundPage'
import { OfficialDashboardPage } from './pages/OfficialDashboardPage'
import { RecountPage } from './pages/RecountPage'
import { ResiliencePage } from './pages/ResiliencePage'

export default function App() {
  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/voter/ballot" element={<BallotPage />} />
        <Route path="/official" element={<OfficialDashboardPage />} />
        <Route path="/official/recount" element={<RecountPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/resilience" element={<ResiliencePage />} />
        <Route path="/login" element={<Navigate to="/official" replace />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </AppShell>
  )
}
