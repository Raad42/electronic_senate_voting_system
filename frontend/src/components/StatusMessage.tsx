type StatusMessageProps = {
  tone: 'success' | 'error' | 'info'
  title: string
  children: React.ReactNode
}

// Reuse one status layout for success, error, and information messages.
export function StatusMessage({ tone, title, children }: StatusMessageProps) {
  return (
    <div className={`status-message status-${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
      <strong>{title}</strong>
      <span>{children}</span>
    </div>
  )
}
