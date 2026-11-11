import { Link } from 'react-router-dom'

export function NotFoundPage() {
  // Keep unknown routes recoverable with a clear return path.
  return <section className="empty-state"><h2>Page not found</h2><p>The requested page does not exist.</p><Link className="button button-primary" to="/">Return to overview</Link></section>
}
