import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ApiError, api, describeError } from '../api/client'
import { StatusMessage } from '../components/StatusMessage'
import type { AuditEvent } from '../types/api'

type ChainStatus = 'CHECKING' | 'VALID' | 'INVALID'

export function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [chainStatus, setChainStatus] = useState<ChainStatus>('CHECKING')
  const [eventFilter, setEventFilter] = useState('ALL')
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [needsAuditor, setNeedsAuditor] = useState(false)

  async function loadEvents() {
    setLoading(true)
    setError('')
    setNeedsAuditor(false)
    try {
      const result = await api.getAuditEvents()
      setEvents(result.events)
      setChainStatus(result.chainStatus === 'VALID' ? 'VALID' : 'INVALID')
      setSelectedEvent(null)
    } catch (err) {
      setChainStatus('INVALID')
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        setNeedsAuditor(true)
        setError(`Only an official signed in with the AUDITOR role can read the audit log. ${describeError(err, '')}`)
      } else {
        setError('The audit service could not verify the event chain. Do not treat the displayed data as trusted.')
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void loadEvents()
  }, [])

  const eventTypes = useMemo(() => ['ALL', ...new Set(events.map((event) => event.eventType))], [events])
  const visibleEvents = eventFilter === 'ALL' ? events : events.filter((event) => event.eventType === eventFilter)

  return (
    <section className="page-stack">
      <div className="page-heading">
        <div>
          <p className="eyebrow">GR05 · Tamper-evident audit logging</p>
          <h2>Audit events</h2>
          <p>Count and recount operations are linked by a verifiable hash chain. Ballot identity is deliberately absent.</p>
        </div>
        <span className={chainStatus === 'VALID' ? 'chain-pill' : 'chain-pill chain-pill-invalid'}>Chain: {chainStatus}</span>
      </div>

      {error && <StatusMessage tone="error" title={needsAuditor ? 'Auditor access required' : 'Audit verification failed'}>{error}</StatusMessage>}
      {needsAuditor && <Link className="button button-primary" to="/official/login?next=/audit">Sign in as auditor</Link>}
      {chainStatus === 'VALID' && !error && <StatusMessage tone="success" title="Hash chain verified">The returned audit events form a valid tamper-evident chain.</StatusMessage>}

      <div className="grid-3">
        <div className="metric-card"><span>Events loaded</span><strong>{events.length}</strong></div>
        <div className="metric-card"><span>Election</span><strong>senate-2026</strong></div>
        <div className="metric-card"><span>Ballot identity links</span><strong>None exposed</strong></div>
      </div>

      <div className="panel audit-toolbar">
        <label>Filter events<select value={eventFilter} onChange={(event) => setEventFilter(event.target.value)}>{eventTypes.map((type) => <option key={type} value={type}>{type === 'ALL' ? 'All event types' : type}</option>)}</select></label>
        <button className="button button-secondary" onClick={() => void loadEvents()} disabled={loading}>{loading ? 'Verifying…' : 'Verify chain again'}</button>
      </div>

      <div className="panel table-panel">
        <div className="table-scroll">
          <table>
            <thead><tr><th>Event</th><th>Scope</th><th>Actor</th><th>Timestamp</th><th>Hash</th></tr></thead>
            <tbody>
              {visibleEvents.map((event) => <tr className={selectedEvent?.eventId === event.eventId ? 'audit-row-selected' : ''} key={event.eventId} onClick={() => setSelectedEvent(event)}><td><strong>{event.eventType}</strong><small>{event.eventId}</small></td><td>{event.state} · {event.electionId}<small>{event.countId ?? 'No count ID'}</small></td><td>{event.actorType}<small>{event.actorId}</small></td><td>{new Date(event.timestamp).toLocaleString()}</td><td><code>{event.eventHash}</code></td></tr>)}
            </tbody>
          </table>
        </div>
        {!loading && !visibleEvents.length && <StatusMessage tone="info" title="No matching events">The audit service returned no events for this filter.</StatusMessage>}
      </div>

      {selectedEvent && (
        <div className="panel audit-detail-panel">
          <div className="panel-heading"><h3>Event details</h3><span className="status-dot">Immutable record</span></div>
          <div className="audit-detail-grid">
            <div><span>Event ID</span><strong>{selectedEvent.eventId}</strong></div>
            <div><span>Previous hash</span><code>{selectedEvent.previousHash}</code></div>
            <div><span>Event hash</span><code>{selectedEvent.eventHash}</code></div>
            <div><span>Resource</span><strong>{selectedEvent.resourceId}</strong></div>
          </div>
        </div>
      )}

      <div className="panel privacy-panel">
        <div className="panel-heading"><h3>Ballot secrecy boundary</h3><span className="status-dot">Protected</span></div>
        <p>Audit events identify the authorised actor and operation, but never expose an elector identifier or provide a ballot lookup key. Attempts to query a ballot by elector identity must be refused and logged as <code>QUERY_REFUSED</code>.</p>
      </div>
    </section>
  )
}
