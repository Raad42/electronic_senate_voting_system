import { FormEvent, useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ApiError, api, describeError } from '../api/client'
import { StatusMessage } from '../components/StatusMessage'
import type { ExclusionResponse, OfficialSession } from '../types/api'

export function RecountPage() {
  const navigate = useNavigate()
  const [session, setSession] = useState<OfficialSession | null>(null)
  const [candidateId, setCandidateId] = useState('CAND-041')
  const [evidenceId, setEvidenceId] = useState('HC-2026-17')
  const [stepUpCode, setStepUpCode] = useState('')
  const [result, setResult] = useState<ExclusionResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [sessionEnded, setSessionEnded] = useState(false)

  useEffect(() => {
    api.getOfficialSession()
      .then(setSession)
      .catch((err) => {
        if (err instanceof ApiError && err.status === 401) {
          navigate('/official/login?next=/official/recount', { replace: true })
          return
        }
        setError(describeError(err, 'The official session could not be verified.'))
      })
      .finally(() => setLoading(false))
  }, [navigate])

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!session || submitting || result?.status === 'APPROVED') return
    setSubmitting(true)
    setError('')
    setResult(null)
    try {
      const response = await api.submitExclusion({
        electionId: session.scope.electionId,
        state: session.scope.state,
        candidateId,
        recountPhase: 'OPEN',
        exclusionGround: 'COURT_ORDER',
        supportingEvidenceId: evidenceId,
        stepUpCode,
      })
      setResult(response)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        // A wrong step-up code ends the session (Milestone 2 Table 11).
        setSession(null)
        setSessionEnded(true)
      }
      setError(`${describeError(err, 'The exclusion request could not be evaluated.')} No election state was changed.`)
    } finally {
      setStepUpCode('')   // a code works once; ask for a fresh one next time
      setSubmitting(false)
    }
  }

  return (
    <section className="page-stack narrow-page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">GR03 · Scope-limited recount authority</p>
          <h2>Submit candidate exclusion</h2>
          <p>The server validates every field before changing election state.</p>
        </div>
        <span className="state-pill">Recount phase: OPEN</span>
      </div>

      {loading && <StatusMessage tone="info" title="Checking official scope">Verifying the delegate session before showing the request form.</StatusMessage>}
      {error && <StatusMessage tone="error" title="Request unavailable">{error}</StatusMessage>}
      {sessionEnded && <Link className="button button-primary" to="/official/login?next=/official/recount">Sign in again</Link>}

      {session && (
        <>
          <div className="scope-banner">
            <strong>Authorised scope</strong>
            <span>Role: {session.role} · State: {session.scope.state} · Election: {session.scope.electionId} · Count: {session.scope.countId ?? 'Not assigned'}</span>
          </div>

          {result?.status === 'APPROVED' && (
            <StatusMessage tone="success" title="Exclusion approved and audit-logged">
              Exclusion {result.exclusionId} was recorded. Audit event: {result.auditEventId}.
              {result.elected && <> Recount result, elected in order: {result.elected.join(', ')}.</>}
            </StatusMessage>
          )}
          {result?.status === 'REJECTED' && <StatusMessage tone="error" title="Exclusion rejected">{result.reason ?? 'The policy service rejected the request.'} No election state was changed.</StatusMessage>}

          <form className="panel form-stack" onSubmit={submit}>
            <label>Candidate<select value={candidateId} onChange={(event) => setCandidateId(event.target.value)} disabled={submitting || result?.status === 'APPROVED'}><option value="CAND-041">CAND-041 (SA)</option><option value="CAND-052">CAND-052 (VIC) — locked</option></select></label>
            <label>Exclusion ground<select defaultValue="COURT_ORDER" disabled={submitting || result?.status === 'APPROVED'}><option value="COURT_ORDER">Court of Disputed Returns order</option><option value="OTHER">Other approved ground</option></select></label>
            <label>Supporting evidence ID<input value={evidenceId} onChange={(event) => setEvidenceId(event.target.value)} disabled={submitting || result?.status === 'APPROVED'} required /></label>
            <label>Step-up one-time code<input value={stepUpCode} onChange={(event) => setStepUpCode(event.target.value.replace(/\D/g, '').slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" placeholder="New 6-digit code (not the one you signed in with)" disabled={submitting || result?.status === 'APPROVED'} required /></label>
            <div className="checklist">
              <strong>Server validation checklist</strong>
              <span>✓ Delegate role and MFA session</span>
              <span>✓ Election and state scope</span>
              <span>✓ Candidate membership</span>
              <span>✓ Exclusion ground and evidence</span>
              <span>✓ Recount phase is open</span>
            </div>
            <button className="button button-primary" type="submit" disabled={submitting || result?.status === 'APPROVED' || stepUpCode.length !== 6}>{submitting ? 'Validating request…' : 'Confirm exclusion'}</button>
            <p className="helper-text">This irreversible action requires backend step-up validation. The frontend does not approve it locally.</p>
          </form>
        </>
      )}
    </section>
  )
}
