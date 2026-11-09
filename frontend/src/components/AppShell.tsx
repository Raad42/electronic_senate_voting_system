import { NavLink } from 'react-router-dom'
import type { PropsWithChildren } from 'react'

export function AppShell({ children }: PropsWithChildren) {
  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Electronic Senate Voting System</p>
          <h1>Secure voting prototype</h1>
        </div>
        <span className="environment-badge">Prototype mode</span>
      </header>

      <nav className="navigation" aria-label="Primary navigation">
        <NavLink to="/" end className={navClassName}>Overview</NavLink>
        <NavLink to="/voter/ballot" className={navClassName}>Voter ballot</NavLink>
        <NavLink to="/official" className={navClassName}>Official console</NavLink>
        <NavLink to="/official/recount" className={navClassName}>Recount</NavLink>
        <NavLink to="/audit" className={navClassName}>Audit log</NavLink>
        <NavLink to="/resilience" className={navClassName}>Resilience</NavLink>
      </nav>

      <main className="main-content">{children}</main>

      <footer className="footer">
        <span>G3 prototype</span>
        <span>Backend remains the security authority</span>
      </footer>
    </div>
  )
}

function navClassName({ isActive }: { isActive: boolean }) {
  return isActive ? 'nav-link nav-link-active' : 'nav-link'
}
