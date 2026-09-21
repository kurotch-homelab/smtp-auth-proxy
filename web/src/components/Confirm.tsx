import { createContext, useContext, useState } from 'react'
import type { ReactNode } from 'react'
import { Modal } from './Modal'
import { Button } from './ui'

const Context = createContext<(message: string) => Promise<boolean>>(() => Promise.resolve(false))
// eslint-disable-next-line react-refresh/only-export-components
export function useConfirm() {
  return useContext(Context)
}
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<{ message: string; resolve: (value: boolean) => void }>()
  const finish = (value: boolean) => {
    pending?.resolve(value)
    setPending(undefined)
  }
  return (
    <Context.Provider
      value={(message) =>
        new Promise<boolean>((resolve) => {
          setPending({ message, resolve })
        })
      }
    >
      {children}
      {pending && (
        <Modal
          open
          title="Confirm action"
          onClose={() => {
            finish(false)
          }}
        >
          <p className="mb-4">{pending.message}</p>
          <div className="flex gap-2">
            <Button
              onClick={() => {
                finish(false)
              }}
            >
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={() => {
                finish(true)
              }}
            >
              Confirm
            </Button>
          </div>
        </Modal>
      )}
    </Context.Provider>
  )
}
