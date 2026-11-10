import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { StatusMessage } from '../components/StatusMessage'
import type { BallotConfig, BallotSubmission, ElectorAuthorisation } from '../types/api'

const electionId = 'SENATE-2026'
const state = 'SA'
type BallotStage = 'authorise' | 'ballot' | 'review' | 'receipt'

export function BallotPage() {
  const [stage, setStage] = useState<BallotStage>('authorise')
  const [authorisation, setAuthorisation] = useState<ElectorAuthorisation | null>(null)
  const [enrolmentId, setEnrolmentId] = useState('ELECTOR-001')
  const [password, setPassword] = useState('demo-password')
  const [config, setConfig] = useState<BallotConfig | null>(null)
  const [selectedCandidate, setSelectedCandidate] = useState('')
  const [submission, setSubmission] = useState<BallotSubmission | null>(null)
  const [loading, setLoading] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (stage !== 'ballot' || config) return
    setLoading(true)
    api.getBallotConfig(state, electionId)
      .then(setConfig)
      .catch(() => setError('The approved ballot configuration could not be loaded.'))
      .finally(() => setLoading(false))
  }, [stage, config])

  async function beginAuthorisation() {
    setLoading(true)
    setError('')
    try {
      const result = await api.obtainElectorAuthorisation(enrolmentId, password, electionId, state)
      setAuthorisation(result)
      setStage('ballot')
    } catch {
      setError('The voting authorisation could not be issued. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  async function submitBallot() {
    if (!config || !authorisation || !selectedCandidate || submitting) return
    setSubmitting(true)
    setError('')
    try {
      const result = await api.submitBallot(
        authorisation.authorisationToken,
        electionId,
        state,
        [{ candidateId: selectedCandidate, rank: 1 }],
        config.configurationVersion,
      )
      setSubmission(result)
      setStage('receipt')
    } catch {
      setError('The ballot was not accepted. Follow the server response before retrying.')
    } finally {
      setSubmitting(false)
    }
  }

  const selectedCandidateDetails = config?.candidates.find((candidate) => candidate.candidateId === selectedCandidate)

  return (
    <section className="page-stack narrow-page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">GR01 · GR02</p>
          <h2>Submit your Senate ballot</h2>
          <p>Each step is shown explicitly. Your identity is not attached to ballot data.</p>
        </div>
        <span className="state-pill">{state} · {electionId}</span>
      </div>

      <ol className="progress-list" aria-label="Voting progress">
        <ProgressStep number="1" label="Authorise" active={stage === 'authorise'} complete={stage !== 'authorise'} />
        <ProgressStep number="2" label="Choose" active={stage === 'ballot'} complete={stage === 'review' || stage === 'receipt'} />
        <ProgressStep number="3" label="Review" active={stage === 'review'} complete={stage === 'receipt'} />
        <ProgressStep number="4" label="Receipt" active={stage === 'receipt'} complete={false} />
      </ol>

      {error && <StatusMessage tone="error" title="Action unavailable">{error}</StatusMessage>}

      {stage === 'authorise' && (
        <form className="panel flow-panel" onSubmit={(event) => { event.preventDefault(); void beginAuthorisation() }}>
          <span className="step-icon">01</span>
          <h3>Get one ballot authorisation</h3>
          <p>The server will issue a short-lived, single-use capability for the {state} election. It does not contain your elector identifier.</p>
          <label className="flow-field">Elector enrolment ID<input value={enrolmentId} onChange={(event) => setEnrolmentId(event.target.value.toUpperCase())} autoComplete="username" required /></label>
          <label className="flow-field">Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required /></label>
          <button className="button button-primary" type="submit" disabled={loading}>
            {loading ? 'Checking eligibility…' : 'Continue to secure ballot'}
          </button>
          <p className="helper-text">The capability expires after 15 minutes and can be consumed only once.</p>
        </form>
      )}

      {stage === 'ballot' && (
        <div className="panel">
          <div className="panel-meta">
            <span>Configuration version: <strong>{config?.configurationVersion ?? 'Loading…'}</strong></span>
            <span>Authorisation valid until {authorisation && new Date(authorisation.expiresAt).toLocaleTimeString()}</span>
          </div>
          {loading && <StatusMessage tone="info" title="Loading ballot">Retrieving the approved election configuration.</StatusMessage>}
          {config && (
            <>
              <fieldset className="candidate-list">
                <legend>Choose one candidate</legend>
                {config.candidates.map((candidate) => (
                  <label className={`candidate-option ${selectedCandidate === candidate.candidateId ? 'candidate-selected' : ''}`} key={candidate.candidateId}>
                    <input type="radio" name="candidate" value={candidate.candidateId} checked={selectedCandidate === candidate.candidateId} onChange={(event) => setSelectedCandidate(event.target.value)} />
                    <span><strong>{candidate.displayName}</strong><small>{candidate.party} · {candidate.candidateId}</small></span>
                  </label>
                ))}
              </fieldset>
              <button className="button button-primary full-width" disabled={!selectedCandidate} onClick={() => setStage('review')}>Review ballot</button>
            </>
          )}
        </div>
      )}

      {stage === 'review' && selectedCandidateDetails && (
        <div className="panel flow-panel">
          <span className="step-icon">03</span>
          <h3>Review before submitting</h3>
          <p>Check your selection. After submission, the single-use authorisation cannot be reused.</p>
          <div className="review-row"><span>Rank 1</span><strong>{selectedCandidateDetails.displayName}</strong><small>{selectedCandidateDetails.party}</small></div>
          <div className="review-actions">
            <button className="button button-secondary" onClick={() => setStage('ballot')} disabled={submitting}>Change selection</button>
            <button className="button button-primary" onClick={submitBallot} disabled={submitting}>{submitting ? 'Submitting securely…' : 'Submit final ballot'}</button>
          </div>
          <p className="helper-text">Do not refresh or submit again while the request is processing. A timeout does not prove that submission failed.</p>
        </div>
      )}

      {stage === 'receipt' && submission && (
        <div className="panel confirmation-panel">
          <span className="confirmation-icon">✓</span>
          <h3>Submission confirmed</h3>
          <p>Your ballot was accepted at {new Date(submission.submittedAt).toLocaleTimeString()}.</p>
          <p className="helper-text">Receipt reference: {submission.submissionId}</p>
          <p className="helper-text">This receipt confirms submission only. It does not reveal your selection.</p>
        </div>
      )}
    </section>
  )
}

function ProgressStep({ number, label, active, complete }: { number: string; label: string; active: boolean; complete: boolean }) {
  return <li className={`progress-step ${active ? 'progress-active' : ''} ${complete ? 'progress-complete' : ''}`}><span>{complete ? '✓' : number}</span><strong>{label}</strong></li>
}
