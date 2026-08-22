import { describe, expect, it, vi } from 'vitest'
import { createWebhookHandler, memoryIdempotencyStore } from '../src/index.js'
import { github, signGitHubWebhook } from '../src/providers/github/index.js'
import { createWebhookRequest } from '../src/testing/index.js'

const SECRET = 'gh_webhook_secret'
const PAYLOAD = { ref: 'refs/heads/main', repository: { full_name: 'acme/api' } }

async function signedRequest(options: { event?: string; secret?: string; delivery?: string } = {}) {
  const body = JSON.stringify(PAYLOAD)
  const headers: Record<string, string> = {
    'x-hub-signature-256': await signGitHubWebhook(body, options.secret ?? SECRET),
    'x-github-delivery': options.delivery ?? '72d3162e-cc78-11e3-81ab-4c9367dc0958',
  }
  if (options.event !== '') headers['x-github-event'] = options.event ?? 'push'
  return createWebhookRequest({ body, headers })
}

describe('github provider', () => {
  const handler = () => createWebhookHandler({ provider: github({ secret: SECRET }) })

  it('takes the event name from the header, not the body', async () => {
    const result = await handler().process(await signedRequest({ event: 'pull_request' }))
    expect(result.ok).toBe(true)
    expect(result.event?.type).toBe('pull_request')
    expect(result.event?.provider).toBe('github')
  })

  it('derives the event id from the signed body, not the unsigned delivery header', async () => {
    // X-GitHub-Delivery is outside the signature, so a captured body replayed
    // with a fresh GUID must not mint a fresh idempotency key.
    const first = await handler().process(await signedRequest({ delivery: 'abc-123' }))
    const second = await handler().process(await signedRequest({ delivery: 'def-456' }))
    expect(first.event?.id).toMatch(/^[0-9a-f]{64}$/)
    expect(second.event?.id).toBe(first.event?.id)
  })

  it('suppresses a replayed body even when the delivery id is fresh', async () => {
    const handled = vi.fn()
    const h = createWebhookHandler({
      provider: github({ secret: SECRET }),
      idempotency: memoryIdempotencyStore(),
      on: { push: handled },
    })

    expect((await h.process(await signedRequest({ delivery: 'original' }))).outcome).toBe('handled')
    const replay = await h.process(await signedRequest({ delivery: 'attacker-fresh' }))
    expect(replay.outcome).toBe('duplicate')
    expect(handled).toHaveBeenCalledOnce()
  })

  it('dispatches to a registered handler', async () => {
    const seen: string[] = []
    const h = handler().on('push', (event) => {
      seen.push(event.type)
    })
    await h.process(await signedRequest())
    expect(seen).toEqual(['push'])
  })

  it('rejects a wrong secret', async () => {
    const result = await handler().process(await signedRequest({ secret: 'wrong' }))
    expect(result.error?.code).toBe('invalid_signature')
  })

  it('rejects the legacy sha1 header', async () => {
    const body = JSON.stringify(PAYLOAD)
    const result = await handler().process(
      createWebhookRequest({
        body,
        headers: { 'x-hub-signature': 'sha1=deadbeef', 'x-github-event': 'push' },
      }),
    )
    expect(result.error?.code).toBe('missing_signature')
  })

  it('fails to parse when the event header is absent', async () => {
    const result = await handler().process(await signedRequest({ event: '' }))
    expect(result.error?.code).toBe('invalid_payload')
  })
})
