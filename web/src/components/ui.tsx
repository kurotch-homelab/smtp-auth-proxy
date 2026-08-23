import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
} from 'react'

/** The building blocks every screen shares, so they stay consistent. */

type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  /** Shows a busy state and prevents a second submission. */
  busy?: boolean
}

const buttonStyles: Record<ButtonVariant, string> = {
  primary: 'bg-accent text-accent-ink hover:opacity-90',
  secondary: 'border border-border bg-surface-raised hover:bg-border/40',
  danger: 'bg-danger text-white hover:opacity-90',
  ghost: 'hover:bg-border/40',
}

export function Button({ variant = 'secondary', busy, disabled, children, ...rest }: ButtonProps) {
  return (
    <button
      {...rest}
      disabled={disabled ?? busy}
      aria-busy={busy}
      className={`inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition
        disabled:cursor-not-allowed disabled:opacity-50 ${buttonStyles[variant]} ${rest.className ?? ''}`}
    >
      {busy && <Spinner />}
      {children}
    </button>
  )
}

export function Spinner() {
  return (
    <span
      role="status"
      aria-label="Working"
      className="inline-block size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"
    />
  )
}

interface FieldProps {
  label: string
  htmlFor?: string
  /** A validation message from the API, shown under the control. */
  error?: string
  /** Explains the field when the label alone is not enough. */
  hint?: ReactNode
  children: ReactNode
}

export function Field({ label, htmlFor, error, hint, children }: FieldProps) {
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={htmlFor} className="text-sm font-medium">
        {label}
      </label>
      {children}
      {hint && <p className="text-xs text-ink-muted">{hint}</p>}
      {error && (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      )}
    </div>
  )
}

const controlClasses =
  'rounded-md border border-border bg-surface px-3 py-1.5 text-sm ' +
  'disabled:cursor-not-allowed disabled:opacity-60'

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`${controlClasses} ${props.className ?? ''}`} />
}

export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={`${controlClasses} ${props.className ?? ''}`} />
}

export function Card({
  title,
  actions,
  children,
}: {
  title?: ReactNode
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="rounded-lg border border-border bg-surface-raised">
      {(title ?? actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-3">
          {title && <h2 className="text-sm font-semibold">{title}</h2>}
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  )
}

type BadgeTone = 'neutral' | 'success' | 'warning' | 'danger' | 'accent'

const badgeStyles: Record<BadgeTone, string> = {
  neutral: 'bg-border/60 text-ink',
  success: 'bg-success/20 text-success',
  warning: 'bg-warning/20 text-warning',
  danger: 'bg-danger/20 text-danger',
  accent: 'bg-accent/20 text-accent',
}

export function Badge({ tone = 'neutral', children }: { tone?: BadgeTone; children: ReactNode }) {
  return (
    <span
      className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${badgeStyles[tone]}`}
    >
      {children}
    </span>
  )
}

/**
 * Shows an error in a way that is useful rather than decorative: the API's own
 * message, which is written to tell an operator what to do.
 */
export function ErrorNotice({ error, className }: { error: unknown; className?: string }) {
  if (!error) return null
  const message = describeError(error)
  return (
    <div
      role="alert"
      className={`rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger ${className ?? ''}`}
    >
      {message}
    </div>
  )
}

/**
 * Turns whatever was thrown into something readable. An Error carries a message
 * written for a person; anything else is at least identified rather than
 * rendered as "[object Object]".
 */
function describeError(error: unknown): string {
  if (error instanceof Error) return error.message
  if (typeof error === 'string') return error
  return 'Something went wrong.'
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 py-10 text-center">
      <p className="font-medium">{title}</p>
      {children && <div className="max-w-prose text-sm text-ink-muted">{children}</div>}
    </div>
  )
}

export function Table({ headers, children }: { headers: ReactNode[]; children: ReactNode }) {
  return (
    // Wide tables scroll inside their own container rather than making the page
    // scroll sideways.
    <div className="overflow-x-auto">
      <table className="w-full min-w-[40rem] border-collapse text-sm">
        <thead>
          <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-ink-muted">
            {headers.map((header, i) => (
              <th key={i} scope="col" className="px-3 py-2 font-medium">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  )
}

export function Row({ children }: { children: ReactNode }) {
  return <tr className="border-b border-border/60 last:border-0">{children}</tr>
}

export function Cell({ children, className }: { children: ReactNode; className?: string }) {
  return <td className={`px-3 py-2 align-top ${className ?? ''}`}>{children}</td>
}
