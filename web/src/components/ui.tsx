import type { ButtonHTMLAttributes, ReactNode, SelectHTMLAttributes } from 'react'
import type { InputProps as FluentInputProps } from '@fluentui/react-components'
import {
  Badge as FluentBadge,
  Button as FluentButton,
  Field as FluentField,
  Input as FluentInput,
  Select as FluentSelect,
  Spinner as FluentSpinner,
  MessageBar,
  MessageBarBody,
  useRestoreFocusTarget,
} from '@fluentui/react-components'

type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost'
interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  busy?: boolean
}
const buttonAppearance = {
  primary: 'primary',
  secondary: 'secondary',
  danger: 'primary',
  ghost: 'subtle',
} as const

export function Button({ variant = 'secondary', busy, disabled, children, ...rest }: ButtonProps) {
  const restoreFocusTarget = useRestoreFocusTarget()
  return (
    <FluentButton
      {...restoreFocusTarget}
      {...rest}
      disabled={disabled || busy}
      aria-busy={busy}
      appearance={buttonAppearance[variant]}
      className={`${variant === 'danger' ? 'app-button-danger' : ''} ${rest.className ?? ''}`}
    >
      {busy && <Spinner />}
      {children}
    </FluentButton>
  )
}

export function Spinner() {
  return <FluentSpinner size="tiny" aria-label="Working" />
}

interface FieldProps {
  label: string
  htmlFor?: string
  error?: string
  hint?: ReactNode
  children: ReactNode
}
export function Field({ label, htmlFor, error, hint, children }: FieldProps) {
  return (
    <FluentField
      label={{ children: label, htmlFor }}
      hint={hint ? <>{hint}</> : undefined}
      validationMessage={error}
      validationState={error ? 'error' : 'none'}
    >
      {children}
    </FluentField>
  )
}

export function Input(props: FluentInputProps) {
  return <FluentInput {...props} className={`app-input ${props.className ?? ''}`} />
}
export function Select({ size: _size, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <FluentSelect {...props} className={`app-input ${props.className ?? ''}`} />
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
    <section className="app-card">
      {(title ?? actions) && (
        <header className="app-card-header">
          {title && <h2>{title}</h2>}
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="app-card-body">{children}</div>
    </section>
  )
}

type BadgeTone = 'neutral' | 'success' | 'warning' | 'danger' | 'accent'
const badgeColors = {
  neutral: 'informative',
  success: 'success',
  warning: 'warning',
  danger: 'danger',
  accent: 'brand',
} as const
export function Badge({ tone = 'neutral', children }: { tone?: BadgeTone; children: ReactNode }) {
  return (
    <FluentBadge appearance="tint" color={badgeColors[tone]} shape="rounded">
      {children}
    </FluentBadge>
  )
}

export function ErrorNotice({ error, className }: { error: unknown; className?: string }) {
  if (!error) return null
  const message =
    error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : 'Something went wrong.'
  return (
    <MessageBar intent="error" role="alert" className={className}>
      <MessageBarBody>{message}</MessageBarBody>
    </MessageBar>
  )
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 py-10 text-center">
      <p className="font-semibold">{title}</p>
      {children && <div className="max-w-prose text-sm text-ink-muted">{children}</div>}
    </div>
  )
}

export function Table({ headers, children }: { headers: ReactNode[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="app-table w-full min-w-[40rem] border-collapse text-sm">
        <thead>
          <tr>
            {headers.map((header, i) => (
              <th key={i} scope="col">
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
  return <tr>{children}</tr>
}
export function Cell({ children, className }: { children: ReactNode; className?: string }) {
  return <td className={className}>{children}</td>
}
