/**
 * Author: Arya
 * Edits:
 *
 * Shared layout with the header and navigation around every page
 *
 * Requirements:
 *     GR01 to GR05 - one place to reach the voter, official, recount, audit and resilience screens
 *
 * Run:
 *     cd frontend && npm install && npm run dev
 *     Then open http://localhost:5173
 *
 * Usage example:
 *     App.tsx wraps all of its routes inside the AppShell component
 *
 * Output:
 *     Each page has the "Secure voting system" header and links to Overview, Voter ballot,
 *     Official console, Recount, Audit log and Resilience
 *     The link for the page you're on is highlighted
 */
import { NavLink } from 'react-router-dom'
import type { PropsWithChildren } from 'react'

export function AppShell({ children }: PropsWithChildren) {
  // Keep the shared shell around every route.
  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Electronic Senate Voting System</p>
          <h1>Secure voting system</h1>
        </div>
      </header>

      {/* Keep route navigation separate from page content. */}
      <nav className="navigation" aria-label="Primary navigation">
        <NavLink to="/" end className={navClassName}>Overview</NavLink>
        <NavLink to="/voter/ballot" className={navClassName}>Voter ballot</NavLink>
        <NavLink to="/official" className={navClassName}>Official console</NavLink>
        <NavLink to="/official/recount" className={navClassName}>Recount</NavLink>
        <NavLink to="/audit" className={navClassName}>Audit log</NavLink>
        <NavLink to="/resilience" className={navClassName}>Resilience</NavLink>
      </nav>

      {/* Swap each page into the same main content region. */}
      <main className="main-content">{children}</main>

      {/* Keep the system identity at the bottom of every page. */}
      <footer className="footer">
        <span>Electronic Senate Voting System</span>
        <span>Backend remains the security authority</span>
      </footer>
    </div>
  )
}

function navClassName({ isActive }: { isActive: boolean }) {
  return isActive ? 'nav-link nav-link-active' : 'nav-link'
}
