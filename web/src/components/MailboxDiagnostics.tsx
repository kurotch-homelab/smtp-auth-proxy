import { useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '@/api/client'
import { useSession } from '@/lib/useSession'
import { Button, ErrorNotice, Field, Input, Spinner } from './ui'
import { useConfirm } from './Confirm'

export function MailboxDiagnostics({ id }: { id: string }) {
  const { can } = useSession()
  const confirm = useConfirm()
  const [recipient, setRecipient] = useState('')
  const [requestId, setRequestId] = useState(() => crypto.randomUUID())
  const [messageId, setMessageId] = useState('')
  const info = useQuery({
    queryKey: ['diagnostics', id],
    queryFn: () => api.mailboxes.diagnostics(id),
  })
  const token = useMutation({ mutationFn: () => api.mailboxes.test(id) })
  const send = useMutation({
    mutationFn: () => api.mailboxes.sendTest(id, { requestId, recipient }),
    onSuccess: (data) => {
      setMessageId(data.messageId)
    },
  })
  const message = useQuery({
    queryKey: ['message', messageId],
    queryFn: () => api.messages.get(messageId),
    enabled: !!messageId,
    refetchInterval: 5_000,
  })
  return (
    <section className="flex flex-col gap-3" aria-label="Diagnostics">
      <h3>Diagnostics</h3>
      <ErrorNotice error={info.error} />
      {info.isLoading ? (
        <Spinner />
      ) : (
        info.data && (
          <>
            <p>
              Destination: {info.data.endpoint || 'Not configured'} · {info.data.mailbox.transport}
            </p>
            <p>Credential expires: {info.data.credential.expiresAt ?? 'Not recorded'}</p>
            <p className="text-sm text-ink-muted">{info.data.verificationScope}</p>
            {can('diagnostics.run') && (
              <>
                <Button
                  busy={token.isPending}
                  onClick={() => {
                    token.mutate()
                  }}
                >
                  Check authentication
                </Button>
                <ErrorNotice error={token.error} />
                {token.data && (
                  <p role="status">
                    {token.data.ok
                      ? 'Token acquisition succeeded. Delivery has not been tested.'
                      : token.data.message}
                  </p>
                )}
                <form
                  className="flex flex-col gap-3"
                  onSubmit={(event) => {
                    event.preventDefault()
                    void (async () => {
                      if (
                        await confirm(
                          `Send one test email from ${info.data.mailbox.address} to ${recipient}? This checks Microsoft 365 acceptance only. It does not verify inbox arrival or device SMTP login.`,
                        )
                      )
                        send.mutate()
                    })()
                  }}
                >
                  <Field label="Test recipient" htmlFor="test-recipient">
                    <Input
                      id="test-recipient"
                      type="email"
                      required
                      disabled={send.isPending || !!messageId}
                      value={recipient}
                      onChange={(e) => {
                        setRecipient(e.target.value)
                        setRequestId(crypto.randomUUID())
                      }}
                    />
                  </Field>
                  <Button
                    type="submit"
                    disabled={!info.data.mailbox.enabled || !!messageId}
                    busy={send.isPending}
                  >
                    Send test email
                  </Button>
                  <ErrorNotice error={send.error} />
                  {send.error && (
                    <p>Retrying uses the same request ID to prevent duplicate mail.</p>
                  )}
                </form>
              </>
            )}
          </>
        )
      )}
      {messageId && (
        <>
          <ErrorNotice error={message.error} />
          {message.isLoading ? (
            <Spinner />
          ) : (
            !message.error &&
            message.data && (
              <p role="status">
                {message.data.status === 'sent'
                  ? 'Microsoft 365 accepted the message. Inbox arrival is not verified.'
                  : `Test message: ${message.data.status}`}
              </p>
            )
          )}
          <Link to={`/messages?message=${messageId}`}>Track test message</Link>
          <Button
            onClick={() => {
              setMessageId('')
              setRequestId(crypto.randomUUID())
              send.reset()
            }}
          >
            Prepare another test
          </Button>
        </>
      )}
    </section>
  )
}
