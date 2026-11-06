import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { StatusMessage } from '../components/StatusMessage'
import type { AuditEvent } from '../types/api'

export function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [chainStatus, setChainStatus] = useState('CHECKING')

  useEffect(() => {
    api.getAuditEvents().then((result) => {
      setEvents(result.events)
      setChainStatus(result.chainStatus)
    })
  }, [])

  return (
    <section className="page-stack">
      <div className="page-heading">
        <div>
          <p className="eyebrow">GR05 · Tamper-evident audit logging</p>
          <h2>Audit events</h2>
          <p>Count and recount operations are linked by a verifiable hash chain.</p>
        </div>
        <span className="chain-pill">Chain: {chainStatus}</span>
      </div>
      <div className="panel table-panel">
        <div className="table-scroll">
          <table>
            <thead><tr><th>Event</th><th>Actor</th><th>Resource</th><th>Timestamp</th><th>Hash</th></tr></thead>
            <tbody>
              {events.map((event) => <tr key={event.eventId}><td><strong>{event.eventType}</strong><small>{event.eventId}</small></td><td>{event.actorType}<small>{event.actorId}</small></td><td>{event.resourceId}</td><td>{new Date(event.timestamp).toLocaleString()}</td><td><code>{event.eventHash}</code></td></tr>)}
            </tbody>
          </table>
        </div>
        {!events.length && <StatusMessage tone="info" title="No events available">The audit service has not returned any events.</StatusMessage>}
      </div>
    </section>
  )
}
