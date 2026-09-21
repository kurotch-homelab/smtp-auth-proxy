import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { FluentProvider, webLightTheme } from '@fluentui/react-components'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { QueuePage } from './Queue'
import { api } from '@/api/client'
import { SessionContext } from '@/lib/sessionContext'
import { ConfirmProvider } from '@/components/Confirm'
import type { Message } from '@/api/types'

const message: Message = {
  id: 'message-1',
  status: 'sending',
  recipients: ['to@example.com'],
  recipientCount: 1,
  sizeBytes: 10,
  envelopeFrom: 'from@example.com',
  receivedAt: '2026-09-21T10:00:00Z',
  attempts: 0,
  lastErrorPermanent: false,
}
afterEach(() => {
  vi.restoreAllMocks()
})
function setup(url: string) {
  vi.spyOn(api.mailboxes, 'list').mockResolvedValue({ items: [], total: 0 })
  vi.spyOn(api.accounts, 'list').mockResolvedValue({ items: [], total: 0 })
  render(
    <FluentProvider theme={webLightTheme}>
      <QueryClientProvider
        client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
      >
        <SessionContext.Provider
          value={{
            session: undefined,
            loading: false,
            can: () => true,
            signIn: async () => {},
            signOut: async () => {},
            refresh: async () => {},
          }}
        >
          <MemoryRouter initialEntries={[url]}>
            <ConfirmProvider>
              <QueuePage />
            </ConfirmProvider>
          </MemoryRouter>
        </SessionContext.Provider>
      </QueryClientProvider>
    </FluentProvider>,
  )
}
it('loads a direct detail URL independently and forbids sending-state actions', async () => {
  const list = vi.spyOn(api.messages, 'list').mockResolvedValue({ items: [], total: 0 })
  const get = vi.spyOn(api.messages, 'get').mockResolvedValue(message)
  setup(
    '/messages?message=message-1&status=failed&mailboxId=mb&accountId=acct&page=2&search=someone',
  )
  expect(await screen.findByRole('button', { name: 'Send now' })).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Hold' })).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Discard' })).toBeDisabled()
  expect(get).toHaveBeenCalledWith('message-1')
  expect(list).toHaveBeenCalledWith(
    expect.objectContaining({
      status: ['failed'],
      mailboxId: 'mb',
      accountId: 'acct',
      offset: 100,
      search: 'someone',
    }),
  )
})
it('opening a detail does not reload or discard the filtered list', async () => {
  const list = vi.spyOn(api.messages, 'list').mockResolvedValue({ items: [message], total: 1 })
  vi.spyOn(api.messages, 'get').mockResolvedValue(message)
  setup('/messages?search=recipient')
  await userEvent.click(await screen.findByRole('button', { name: 'Details' }))
  await screen.findByRole('button', { name: 'Discard' })
  await userEvent.click(screen.getByRole('button', { name: 'Close details' }))
  await waitFor(() => {
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
  expect(list).toHaveBeenCalledTimes(1)
  expect(screen.getByRole('textbox', { name: 'Search by sender or recipient' })).toHaveValue(
    'recipient',
  )
})
it('shows a detail fetch failure rather than using an old selected row', async () => {
  vi.spyOn(api.messages, 'list').mockResolvedValue({ items: [message], total: 1 })
  vi.spyOn(api.messages, 'get').mockRejectedValue(new Error('Message no longer exists'))
  setup('/messages?message=message-1')
  expect(await screen.findByText('Message no longer exists')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Send now' })).not.toBeInTheDocument()
})
