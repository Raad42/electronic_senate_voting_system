import { FormEvent, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api, describeError } from '../api/client'
import { StatusMessage } from '../components/StatusMessage'
import type { OfficialRole } from '../types/api'

const roles: { value: OfficialRole; label: string }[] = [
  { value: 'RECOUNT_DELEGATE', label: 'Recount delegate' },
  { value: 'AUDITOR', label: 'Auditor' },
  { value: 'COUNT_OPERATOR', label: 'Count operator' },
  { value: 'ELECTION_OFFICIAL', label: 'Election official' },
]

/** Only internal paths are allowed as a return address (no open redirect). */
function safeNext(next: string | null): string {
  return next && next.startsWith('/') && !next.startsWith('//') ? next : '/official'
}

export function OfficialLoginPage() {
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [otp, setOtp] = useState('')
  const [role, setRole] = useState<OfficialRole>('RECOUNT_DELEGATE')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (submitting) return
    setSubmitting(true)
    setError('')
    try {
      await api.officialLogin({ username: username.trim(), password, otp, role })
      navigate(safeNext(params.get('next')), { replace: true })
    } catch (err) {
      setPassword('')
      setOtp('')
      setError(describeError(err, 'Sign-in failed. Check your details and try again.'))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <section className="page-stack narrow-page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Official access · Password + one-time code</p>
          <h2>Official sign-in</h2>
          <p>Choose the one role this session will use. To switch roles, sign out and sign in again.</p>
        </div>
      </div>

      {error && <StatusMessage tone="error" title="Sign-in refused">{error}</StatusMessage>}

      <form className="panel form-stack" onSubmit={submit}>
        <label>Username<input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" maxLength={64} required disabled={submitting} /></label>
        <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" maxLength={256} required disabled={submitting} /></label>
        <label>One-time code<input value={otp} onChange={(event) => setOtp(event.target.value.replace(/\D/g, '').slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" placeholder="6 digits" required disabled={submitting} /></label>
        <label>Active role<select value={role} onChange={(event) => setRole(event.target.value as OfficialRole)} disabled={submitting}>{roles.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}</select></label>
        <button className="button button-primary" type="submit" disabled={submitting || otp.length !== 6}>{submitting ? 'Signing in…' : 'Sign in'}</button>
        <p className="helper-text">Five failed attempts lock the account for 15 minutes. Each one-time code works once.</p>
      </form>
    </section>
  )
}
