import type { ReactNode } from 'react'
import {
  Button,
  Dialog,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
} from '@fluentui/react-components'
import { Dismiss24Regular } from '@fluentui/react-icons'

/** Fluent owns focus trapping, labeling, Escape, and focus restoration. */
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
  return (
    <Dialog
      open={open}
      onOpenChange={(_, data) => {
        if (!data.open) onClose()
      }}
    >
      <DialogSurface className="app-dialog">
        <DialogBody>
          <DialogTitle
            action={
              <Button
                appearance="subtle"
                aria-label="Close"
                icon={<Dismiss24Regular />}
                onClick={onClose}
              />
            }
          >
            {title}
          </DialogTitle>
          <DialogContent className="app-dialog-content">{children}</DialogContent>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  )
}
