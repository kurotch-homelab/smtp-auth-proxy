import { useId } from 'react'
import type { ReactNode } from 'react'
import {
  Button,
  DrawerBody,
  DrawerHeader,
  DrawerHeaderTitle,
  OverlayDrawer,
} from '@fluentui/react-components'
import { Dismiss24Regular } from '@fluentui/react-icons'

export function DetailDrawer({
  title,
  onClose,
  actions,
  children,
}: {
  title: string
  onClose: () => void
  actions?: ReactNode
  children: ReactNode
}) {
  const titleId = useId()
  return (
    <OverlayDrawer
      open
      position="end"
      size="medium"
      aria-labelledby={titleId}
      onOpenChange={(_, data) => {
        if (!data.open) onClose()
      }}
      className="app-detail-drawer"
    >
      <DrawerHeader>
        <DrawerHeaderTitle
          id={titleId}
          action={
            <Button
              appearance="subtle"
              icon={<Dismiss24Regular />}
              aria-label="Close details"
              onClick={onClose}
            />
          }
        >
          {title}
        </DrawerHeaderTitle>
      </DrawerHeader>
      <DrawerBody>
        <div className="mb-6 flex flex-wrap gap-2">{actions}</div>
        {children}
      </DrawerBody>
    </OverlayDrawer>
  )
}
