import { useState } from 'react'
import { StatusMessage } from '../components/StatusMessage'

type FailureCase = {
  status: string
  code: string
  title: string
  explanation: string
  behaviour: string
  tone: 'error' | 'info'
}

// These fixed cases preview safe frontend handling of backend failures.
const failureCases: FailureCase[] = [
  {
    status: '401',
    code: 'AUTHENTICATION_REQUIRED',
    title: 'Session expired',
    explanation: 'The request has no valid authentication context.',
    behaviour: 'Clear local session state and return the user to sign-in. Do not retry with the same credentials automatically.',
    tone: 'error',
  },
  {
    status: '403',
    code: 'SCOPE_DENIED',
    title: 'Action not permitted',
    explanation: 'The account is known but its role or scope does not allow this operation.',
    behaviour: 'Show access denied and keep the protected action unchanged. Do not offer a client-side bypass.',
    tone: 'error',
  },
  {
    status: '409',
    code: 'AUTHORISATION_REPLAY',
    title: 'Already used or conflicting action',
    explanation: 'A single-use capability may already have been consumed, or the state changed.',
    behaviour: 'Lock the submission flow and ask the user to begin a new authorised flow. Never submit again automatically.',
    tone: 'error',
  },
  {
    status: '429',
    code: 'RATE_LIMITED',
    title: 'Too many requests',
    explanation: 'The service is protecting the voting path from excessive or automated requests.',
    behaviour: 'Show a retry-after message and disable the action temporarily. Do not busy-loop or increase request volume.',
    tone: 'info',
  },
  {
    status: '503',
    code: 'SERVICE_UNAVAILABLE',
    title: 'Service temporarily unavailable',
    explanation: 'The backend could not safely evaluate the request.',
    behaviour: 'Fail closed. Never display a success receipt unless the server confirms acceptance.',
    tone: 'info',
  },
]

export function ResiliencePage() {
  const [selected, setSelected] = useState<FailureCase | null>(null)

  return (
    <section className="page-stack">
      <div className="page-heading">
        <div>
          <p className="eyebrow">GR04 · Availability and resilience</p>
          <h2>Safe failure states</h2>
          <p>Choose a response to preview how the frontend behaves when a security check cannot succeed.</p>
        </div>
        <span className="state-pill">Fail closed</span>
      </div>

      {selected && (
        <StatusMessage tone={selected.tone} title={`${selected.status} · ${selected.title}`}>
          {selected.behaviour}
        </StatusMessage>
      )}

      <div className="resilience-grid">
        {failureCases.map((failureCase) => (
          <article className={`resilience-card ${selected?.status === failureCase.status ? 'resilience-card-selected' : ''}`} key={failureCase.status}>
            <span className="error-code">HTTP {failureCase.status} · {failureCase.code}</span>
            <h3>{failureCase.title}</h3>
            <p>{failureCase.explanation}</p>
            <button className="button button-secondary" onClick={() => setSelected(failureCase)}>Preview behaviour</button>
          </article>
        ))}
      </div>

      <div className="panel">
        <div className="panel-heading"><h3>Prototype boundary</h3><span className="status-dot">Backend enforced</span></div>
        <p className="helper-text">This screen documents and demonstrates frontend handling. Actual rate limiting, authentication and fail-closed decisions remain enforced by the API and Nginx layer.</p>
      </div>
    </section>
  )
}
