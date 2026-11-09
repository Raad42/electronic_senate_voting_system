import { Link } from 'react-router-dom'

export function HomePage() {
  return (
    <section className="page-stack">
      <div className="hero-card">
        <p className="eyebrow">Phase 1 frontend foundation</p>
        <h2>One clear interface for secure election operations.</h2>
        <p className="hero-copy">
          This prototype separates the voter journey from official and audit operations. Server
          responses remain authoritative for every security decision.
        </p>
        <div className="hero-actions">
          <Link className="button button-primary" to="/voter/ballot">Open voter flow</Link>
          <Link className="button button-secondary" to="/official">Open official console</Link>
        </div>
      </div>

      <div className="grid-3">
        <article className="feature-card">
          <span className="feature-number">01</span>
          <h3>Single-use ballot access</h3>
          <p>Authorisation is treated as a capability and is never displayed as voter identity.</p>
        </article>
        <article className="feature-card">
          <span className="feature-number">02</span>
          <h3>Scoped official actions</h3>
          <p>Official screens show role, election, state and recount scope before an action.</p>
        </article>
        <article className="feature-card">
          <span className="feature-number">03</span>
          <h3>Verifiable audit trail</h3>
          <p>Counting and recount events expose chain status and tamper-evident hashes.</p>
        </article>
      </div>
    </section>
  )
}
