/**
 * Author: Arya
 * Edits:
 *
 * Official console that shows the signed-in role and scope before any protected action
 *
 * Requirements:
 *     GR03 - the session is checked with the server first, and anyone without a session is sent to sign in
 *
 * Run:
 *     cd frontend && npm run dev
 *     Then open /official
 *
 * Usage example:
 *     Open /official while signed in as rd.sa, then open it again after signing out
 *
 * Output:
 *     The first visit shows the role RECOUNT_DELEGATE for senate-2026 in SA
 *     The second visit goes straight to the sign-in page
 */
import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ApiError, api, describeError } from '../api/client'
import { StatusMessage } from '../components/StatusMessage'
import type { OfficialSession } from '../types/api'

export function OfficialDashboardPage() {
  const navigate = useNavigate()
  const [session, setSession] = useState<OfficialSession | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  // Load the official scope before exposing protected actions.
  useEffect(() => {
    api.getOfficialSession()
      .then(setSession)
      .catch((err) => {
        if (err instanceof ApiError && err.status === 401) {
          navigate('/official/login?next=/official', { replace: true })
          return
        }
        setError(describeError(err, 'Your official session could not be verified.'))
      })
      .finally(() => setLoading(false))
  }, [navigate])

  // End the session before returning to the official sign-in page.
  async function signOut() {
    await api.officialLogout().catch(() => undefined)
    navigate('/official/login', { replace: true })
  }

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
      {error && <StatusMessage tone="error" title="Session unavailable">{error}</StatusMessage>}

      {session && (
        <>
          <div className="grid-3">
            <div className="metric-card"><span>Role</span><strong>{session.role}</strong></div>
            <div className="metric-card"><span>State scope</span><strong>{session.scope.state ?? 'All (read-only)'}</strong></div>
            <div className="metric-card"><span>Election</span><strong>{session.scope.electionId ?? 'All (read-only)'}</strong></div>
          </div>
          <div className="panel">
            <div className="panel-heading"><h3>Protected actions</h3><span className="status-dot">Session active{session.operatorId ? ` · ${session.operatorId}` : ''}</span></div>
            <div className="action-list">
              <div><strong>Submit candidate exclusion</strong><span>Requires evidence, scope validation and audit logging.</span><Link to="/official/recount">Open</Link></div>
              <div><strong>Review audit chain</strong><span>Inspect count and recount events without ballot identity links.</span><Link to="/audit">Open</Link></div>
            </div>
          </div>
          <button className="button button-secondary" onClick={() => void signOut()}>Sign out</button>
        </>
      )}
    </section>
  )
}
