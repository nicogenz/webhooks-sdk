import { describe, expect, it, vi } from 'vitest'
import type { WebhookProvider } from '../src/index.js'
import { createWebhookHandler, memoryIdempotencyStore, WebhookRouter } from '../src/index.js'
import { github, signGitHubWebhook } from '../src/providers/github/index.js'
import { signStripeWebhook, stripe } from '../src/providers/stripe/index.js'
import { createWebhookRequest, eventRecorder } from '../src/testing/index.js'

const SECRET = 'whsec_test'
const NOW = new Date('2026-08-20T12:00:00Z')

async function stripeRequest(id = 'evt_1') {
  const body = JSON.stringify({
    id,
    object: 'event',
    type: 'charge.refunded',
    created: Math.floor(NOW.getTime() / 1000),
    data: { object: {} },
  })
  const signature = await signStripeWebhook(body, SECRET, Math.floor(NOW.getTime() / 1000))
  return createWebhookRequest({
    body,
    headers: { 'stripe-signature': signature },
    url: 'https://example.test/api/webhooks/stripe',
  })
}

describe('createWebhookHandler', () => {
  it('runs onEvent before the type handler, and both fire', async () => {
    const order: string[] = []
    const handler = createWebhookHandler({
      provider: stripe({ secret: SECRET }),
      now: () => NOW,
      onEvent: () => {
        order.push('onEvent')
      },
      on: {
        'charge.refunded': () => {
          order.push('typed')
        },
      },
    })

    await handler.process(await stripeRequest())
    expect(order).toEqual(['onEvent', 'typed'])
  })

  it('calls onUnhandled only when nothing matched', async () => {
    const onUnhandled = vi.fn()
    const handler = createWebhookHandler({
      provider: stripe({ secret: SECRET }),
      now: () => NOW,
      onUnhandled,
    })

    await handler.process(await stripeRequest())
    expect(onUnhandled).toHaveBeenCalledOnce()

    handler.on('charge.refunded', () => {})
    await handler.process(await stripeRequest())
    expect(onUnhandled).toHaveBeenCalledOnce()
  })

  it('runs several handlers registered for the same type', async () => {
    const calls: number[] = []
    const handler = createWebhookHandler({ provider: stripe({ secret: SECRET }), now: () => NOW })
      .on('charge.refunded', () => {
        calls.push(1)
      })
      .on('charge.refunded', () => {
        calls.push(2)
      })

    await handler.process(await stripeRequest())
    expect(calls).toEqual([1, 2])
  })

  it('suppresses a redelivered event id', async () => {
    const handled = vi.fn()
    const handler = createWebhookHandler({
      provider: stripe({ secret: SECRET }),
      now: () => NOW,
      idempotency: memoryIdempotencyStore(),
      on: { 'charge.refunded': handled },
    })

    const first = await handler.process(await stripeRequest('evt_dup'))
    const second = await handler.process(await stripeRequest('evt_dup'))

    expect(first.outcome).toBe('handled')
    expect(second.outcome).toBe('duplicate')
    expect(handled).toHaveBeenCalledOnce()
    // A duplicate is acknowledged, not rejected — otherwise it is redelivered forever.
    expect(second.ok).toBe(true)
  })

  it('re-runs the handler when a failed delivery is retried', async () => {
    // Remembering before dispatch would make the retry of a failed handler
    // look like a duplicate — acknowledged and never re-run — silently
    // dropping the event the 500 was supposed to bring back.
    const handled = vi
      .fn()
      .mockRejectedValueOnce(new Error('transient outage'))
      .mockResolvedValue(undefined)
    const handler = createWebhookHandler({
      provider: stripe({ secret: SECRET }),
      now: () => NOW,
      idempotency: memoryIdempotencyStore(),
      on: { 'charge.refunded': handled },
    })

    const first = await handler.process(await stripeRequest('evt_retry'))
    expect(first.ok).toBe(false)
    expect(first.error?.status).toBe(500)

    const second = await handler.process(await stripeRequest('evt_retry'))
    expect(second.outcome).toBe('handled')
    expect(handled).toHaveBeenCalledTimes(2)

    const third = await handler.process(await stripeRequest('evt_retry'))
    expect(third.outcome).toBe('duplicate')
  })

  it('still processes a different event id', async () => {
    const handled = vi.fn()
    const handler = createWebhookHandler({
      provider: stripe({ secret: SECRET }),
      now: () => NOW,
      idempotency: memoryIdempotencyStore(),
      on: { 'charge.refunded': handled },
    })

    await handler.process(await stripeRequest('evt_a'))
    await handler.process(await stripeRequest('evt_b'))
    expect(handled).toHaveBeenCalledTimes(2)
  })

  it('answers a handshake without verifying or dispatching', async () => {
    const verify = vi.fn()
    const provider: WebhookProvider = {
      id: 'challenger',
      name: 'Challenger',
      verify,
      parse: async () => {
        throw new Error('should not parse')
      },
      handshake: async (raw) => {
        const body = raw.json<{ type?: string; challenge?: string }>()
        return body.type === 'url_verification'
          ? new Response(body.challenge ?? '', { status: 200 })
          : undefined
      },
    }

    const handler = createWebhookHandler({ provider })
    const response = await handler.fetch(
      createWebhookRequest({ body: { type: 'url_verification', challenge: 'abc123' } }),
    )

    expect(await response.text()).toBe('abc123')
    expect(verify).not.toHaveBeenCalled()
  })

  it('never lets a throwing onError mask the original failure', async () => {
    const handler = createWebhookHandler({
      provider: stripe({ secret: SECRET }),
      now: () => NOW,
      onError: () => {
        throw new Error('logger exploded')
      },
    })

    const result = await handler.process(createWebhookRequest({ body: {} }))
    expect(result.error?.code).toBe('missing_signature')
  })

  it('records events for assertions', async () => {
    const recorder = eventRecorder()
    const handler = createWebhookHandler({
      provider: stripe({ secret: SECRET }),
      now: () => NOW,
      onEvent: recorder.record,
    })

    await handler.process(await stripeRequest())
    expect(recorder.types).toEqual(['charge.refunded'])
  })
})

describe('WebhookRouter', () => {
  const build = () =>
    new WebhookRouter({
      providers: {
        stripe: stripe({ secret: SECRET }),
        github: github({ secret: 'gh_secret' }),
      },
      now: () => NOW,
    })

  it('routes by the last path segment', async () => {
    const seen: string[] = []
    const router = build().on('stripe', 'charge.refunded', (event) => {
      seen.push(`${event.provider}:${event.type}`)
    })

    const response = await router.fetch(await stripeRequest())
    expect(response.status).toBe(200)
    expect(seen).toEqual(['stripe:charge.refunded'])
  })

  it('keeps providers isolated', async () => {
    const body = JSON.stringify({ ref: 'refs/heads/main' })
    const router = build()
    const response = await router.fetch(
      createWebhookRequest({
        body,
        url: 'https://example.test/api/webhooks/github',
        headers: {
          'x-hub-signature-256': await signGitHubWebhook(body, 'gh_secret'),
          'x-github-event': 'push',
          'x-github-delivery': 'd-1',
        },
      }),
    )
    expect(response.status).toBe(200)
  })

  it('404s an unregistered slug', async () => {
    const response = await build().fetch(
      createWebhookRequest({ body: {}, url: 'https://example.test/api/webhooks/paddle' }),
    )
    expect(response.status).toBe(404)
    expect(await response.json()).toMatchObject({ error: 'unknown_provider' })
  })

  it('throws when registering a handler for an unknown provider', () => {
    expect(() => build().on('paddle', 'x', () => {})).toThrow(/No provider registered/)
  })
})

describe('memoryIdempotencyStore', () => {
  it('forgets a key after its ttl', () => {
    let clock = 0
    const store = memoryIdempotencyStore({ ttlMs: 1000, now: () => clock })

    store.remember('a')
    expect(store.seen('a')).toBe(true)
    clock = 1001
    expect(store.seen('a')).toBe(false)
  })

  it('evicts the oldest keys past maxSize', () => {
    const store = memoryIdempotencyStore({ maxSize: 2, now: () => 0 })
    store.remember('a')
    store.remember('b')
    store.remember('c')
    expect(store.seen('a')).toBe(false)
    expect(store.seen('c')).toBe(true)
  })
})

describe('blank event ids', () => {
  // Regression: a provider yielding an empty id once collapsed every
  // idempotency key to `provider:`, so the first delivery suppressed all
  // later ones as duplicates — acknowledged with a 200, never retried.
  const idless: WebhookProvider = {
    id: 'idless',
    name: 'Idless',
    verify: async () => {},
    parse: async (raw) => ({
      id: '',
      provider: 'idless',
      type: raw.header('x-event') ?? 'unknown',
      timestamp: NOW,
      payload: {},
      raw,
    }),
  }

  it('processes every delivery instead of deduping on a blank key', async () => {
    const seen = vi.fn()
    const handler = createWebhookHandler({
      provider: idless,
      idempotency: memoryIdempotencyStore(),
      onEvent: seen,
    })

    const outcomes = []
    for (const type of ['file.added', 'file.removed', 'file.renamed']) {
      const result = await handler.process(
        createWebhookRequest({ body: {}, headers: { 'x-event': type } }),
      )
      outcomes.push(result.outcome)
    }

    expect(outcomes).toEqual(['unhandled', 'unhandled', 'unhandled'])
    expect(seen).toHaveBeenCalledTimes(3)
  })
})

describe('handshake ordering', () => {
  // Two classes of handshake, and the provider declares which it is. Getting
  // this backwards breaks endpoint setup in opposite ways: an unsigned
  // challenge cannot be verified because no secret exists yet, while a signed
  // one must be rejected when the signature is bad or Discord refuses the URL.
  const build = (signedHandshake: boolean, calls: string[]): WebhookProvider => ({
    id: 'probe',
    name: 'Probe',
    signedHandshake,
    verify: async () => {
      calls.push('verify')
    },
    parse: async (raw) => ({
      id: 'e1',
      provider: 'probe',
      type: 'thing',
      timestamp: NOW,
      payload: {},
      raw,
    }),
    handshake: async (raw) => {
      calls.push('handshake')
      return raw.json<{ challenge?: boolean }>().challenge
        ? new Response('ok', { status: 200 })
        : undefined
    },
  })

  it('verifies before answering when the handshake is signed', async () => {
    const calls: string[] = []
    await createWebhookHandler({ provider: build(true, calls) }).process(
      createWebhookRequest({ body: { challenge: true } }),
    )
    expect(calls).toEqual(['verify', 'handshake'])
  })

  it('answers before verifying when the handshake is unsigned', async () => {
    const calls: string[] = []
    await createWebhookHandler({ provider: build(false, calls) }).process(
      createWebhookRequest({ body: { challenge: true } }),
    )
    expect(calls).toEqual(['handshake'])
  })

  it('verifies once, not twice, for an ordinary delivery either way', async () => {
    for (const signedHandshake of [true, false]) {
      const calls: string[] = []
      await createWebhookHandler({ provider: build(signedHandshake, calls) }).process(
        createWebhookRequest({ body: { challenge: false } }),
      )
      expect(calls.filter((c) => c === 'verify')).toHaveLength(1)
    }
  })
})
