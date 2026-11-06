import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { StatusMessage } from '../components/StatusMessage'
import type { OfficialSession } from '../types/api'

export function OfficialDashboardPage() {
  const [session, setSession] = useState<OfficialSession | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getOfficialSession().then(setSession).finally(() => setLoading(false))
  }, [])

  return (
    <section className="page-stack">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Official access · MFA verified</p>
          <h2>Operations console</h2>
          <p>Every action is checked again by the policy service and recorded in the audit chain.</p>
        </div>
        <Link className="button button-primary" to="/official/recount">Start recount workflow</Link>
      </div>

      {loading && <StatusMessage tone="info" title="Loading session">Checking your authorised scope.</StatusMessage>}

      {session && (
        <>
          <div className="grid-3">
            <div className="metric-card"><span>Role</span><strong>{session.role}</strong></div>
            <div className="metric-card"><span>State scope</span><strong>{session.scope.state}</strong></div>
            <div className="metric-card"><span>Election</span><strong>{session.scope.electionId}</strong></div>
          </div>
          <div className="panel">
            <div className="panel-heading"><h3>Protected actions</h3><span className="status-dot">Session active</span></div>
            <div className="action-list">
              <div><strong>Submit candidate exclusion</strong><span>Requires evidence, scope validation and audit logging.</span><Link to="/official/recount">Open</Link></div>
              <div><strong>Review audit chain</strong><span>Inspect count and recount events without ballot identity links.</span><Link to="/audit">Open</Link></div>
            </div>
          </div>
        </>
      )}
    </section>
  )
}
