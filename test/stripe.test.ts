import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createWebhookHandler } from '../src/index.js'
import {
  parseStripeSignatureHeader,
  signStripeWebhook,
  stripe,
} from '../src/providers/stripe/index.js'
import { createWebhookRequest } from '../src/testing/index.js'

const SECRET = 'whsec_test_secret'
const NOW = new Date('2026-08-20T12:00:00Z')
const TIMESTAMP = Math.floor(NOW.getTime() / 1000)

const EVENT = {
  id: 'evt_test_123',
  object: 'event' as const,
  type: 'payment_intent.succeeded',
  created: TIMESTAMP,
  api_version: '2026-01-01',
  livemode: false,
  data: { object: { id: 'pi_123', amount: 4200, currency: 'eur' } },
}

async function signedRequest(
  overrides: { body?: string; secret?: string; timestamp?: number } = {},
) {
  const body = overrides.body ?? JSON.stringify(EVENT)
  const signature = await signStripeWebhook(
    body,
    overrides.secret ?? SECRET,
    overrides.timestamp ?? TIMESTAMP,
  )
  return createWebhookRequest({ body, headers: { 'stripe-signature': signature } })
}

function handlerFor(secret: string | string[] = SECRET) {
  return createWebhookHandler({
    provider: stripe({ secret }),
    now: () => NOW,
  })
}

describe('parseStripeSignatureHeader', () => {
  it('collects every v1 candidate', () => {
    expect(parseStripeSignatureHeader('t=1614556800,v1=aaa,v1=bbb')).toEqual({
      timestamp: 1614556800,
      signatures: ['aaa', 'bbb'],
    })
  })

  it('ignores unknown schemes such as v0', () => {
    expect(parseStripeSignatureHeader('t=1,v0=old,v1=new')?.signatures).toEqual(['new'])
  })

  it('returns null without a timestamp or a v1', () => {
    expect(parseStripeSignatureHeader('v1=aaa')).toBeNull()
    expect(parseStripeSignatureHeader('t=1')).toBeNull()
  })
})

describe('stripe provider', () => {
  let handled: unknown[]

  beforeEach(() => {
    handled = []
  })

  it('accepts a correctly signed request and dispatches it', async () => {
    const handler = handlerFor().on('payment_intent.succeeded', (event) => {
      handled.push(event.payload)
    })

    const result = await handler.process(await signedRequest())

    expect(result.ok).toBe(true)
    expect(result.outcome).toBe('handled')
    expect(result.event?.id).toBe('evt_test_123')
    expect(result.event?.timestamp).toEqual(NOW)
    expect(handled).toHaveLength(1)
  })

  it('reports unhandled for an event with no registered handler', async () => {
    const result = await handlerFor().process(await signedRequest())
    expect(result.outcome).toBe('unhandled')
    expect(result.ok).toBe(true)
  })

  it('rejects a signature made with the wrong secret', async () => {
    const result = await handlerFor().process(await signedRequest({ secret: 'whsec_wrong' }))
    expect(result.error?.code).toBe('invalid_signature')
    expect(result.error?.status).toBe(401)
  })

  it('rejects a body tampered with after signing', async () => {
    const body = JSON.stringify(EVENT)
    const signature = await signStripeWebhook(body, SECRET, TIMESTAMP)
    const tampered = body.replace('4200', '1')

    const result = await handlerFor().process(
      createWebhookRequest({ body: tampered, headers: { 'stripe-signature': signature } }),
    )

    expect(result.error?.code).toBe('invalid_signature')
  })

  it('rejects a replayed request outside the tolerance window', async () => {
    const result = await handlerFor().process(await signedRequest({ timestamp: TIMESTAMP - 3600 }))
    expect(result.error?.code).toBe('timestamp_out_of_tolerance')
  })

  it('accepts a timestamp inside the tolerance window', async () => {
    const result = await handlerFor().process(await signedRequest({ timestamp: TIMESTAMP - 120 }))
    expect(result.ok).toBe(true)
  })

  it('rejects a request with no signature header', async () => {
    const result = await handlerFor().process(createWebhookRequest({ body: JSON.stringify(EVENT) }))
    expect(result.error?.code).toBe('missing_signature')
    expect(result.error?.status).toBe(400)
  })

  it('accepts either secret during a rotation', async () => {
    const handler = handlerFor(['whsec_old', 'whsec_new'])
    expect((await handler.process(await signedRequest({ secret: 'whsec_old' }))).ok).toBe(true)
    expect((await handler.process(await signedRequest({ secret: 'whsec_new' }))).ok).toBe(true)
  })

  it('fails configuration when no secret is given', async () => {
    const result = await createWebhookHandler({ provider: stripe({ secret: '' }) }).process(
      await signedRequest(),
    )
    expect(result.error?.code).toBe('invalid_configuration')
  })

  it('returns the right status codes over fetch', async () => {
    const handler = handlerFor()
    expect((await handler.fetch(await signedRequest())).status).toBe(200)
    expect((await handler.fetch(await signedRequest({ secret: 'nope' }))).status).toBe(401)
  })

  it('surfaces a throwing handler as a 500 so Stripe retries', async () => {
    const onError = vi.fn()
    const handler = createWebhookHandler({
      provider: stripe({ secret: SECRET }),
      now: () => NOW,
      onError,
      on: {
        'payment_intent.succeeded': () => {
          throw new Error('database is down')
        },
      },
    })

    const response = await handler.fetch(await signedRequest())

    expect(response.status).toBe(500)
    expect(onError).toHaveBeenCalledOnce()
    expect(onError.mock.calls[0]?.[0].code).toBe('handler_failed')
  })
})
