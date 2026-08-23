import { useState } from 'react'

import { Button } from './ui'

/**
 * Shows a value that has to be copied somewhere else, with a copy button.
 *
 * Used for generated passwords and the tenant PowerShell: both are shown once
 * or are long enough that retyping them is a source of mistakes.
 */
export function CopyField({
  value,
  label,
  multiline,
}: {
  value: string
  label?: string
  multiline?: boolean
}) {
  const [copied, setCopied] = useState(false)

  const copy = () => {
    // The clipboard API needs a secure context; fall back to selecting the text
    // so the value is still usable over plain http.
    navigator.clipboard
      ?.writeText(value)
      .then(() => {
        setCopied(true)
        setTimeout(() => {
          setCopied(false)
        }, 2000)
      })
      .catch(() => {
        setCopied(false)
      })
  }

  return (
    <div className="flex flex-col gap-1">
      {label && <p className="text-xs uppercase tracking-wide text-ink-muted">{label}</p>}
      <div className="flex items-start gap-2">
        <pre className="min-w-0 flex-1 overflow-x-auto rounded-md border border-border bg-surface-raised p-2 text-xs">
          <code>{value}</code>
        </pre>
        <Button onClick={copy} aria-label="Copy to clipboard">
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>
      {multiline && <span className="sr-only">{value}</span>}
    </div>
  )
}
