import { useEffect, useRef } from 'react'
import type { ReactNode } from 'react'

/**
 * A dialog built on <dialog>, so the browser handles the focus trap, the
 * backdrop and Escape rather than this reimplementing all three badly.
 */
export function Modal({
  title,
  open,
  onClose,
  children,
}: {
  title: string
  open: boolean
  onClose: () => void
  children: ReactNode
}) {
  const ref = useRef<HTMLDialogElement>(null)

  useEffect(() => {
    const dialog = ref.current
    if (!dialog) return

    if (open && !dialog.open) {
      dialog.showModal()
    } else if (!open && dialog.open) {
      dialog.close()
    }
  }, [open])

  return (
    <dialog
      ref={ref}
      onClose={onClose}
      // Clicking the backdrop closes it, which is what people expect.
      onClick={(event) => {
        if (event.target === ref.current) onClose()
      }}
      className="w-full max-w-lg rounded-lg border border-border bg-surface p-0 text-ink backdrop:bg-black/40"
    >
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <h2 className="text-sm font-semibold">{title}</h2>
        <button
          type="button"
          aria-label="Close"
          onClick={onClose}
          className="rounded px-2 py-1 text-sm hover:bg-border/40"
        >
          ✕
        </button>
      </div>
      <div className="p-4">{children}</div>
    </dialog>
  )
}
