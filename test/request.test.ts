import { describe, expect, it } from 'vitest'
import { PayloadParseError, toRawWebhook, WebhookRouter } from '../src/index.js'
import { github, signGitHubWebhook } from '../src/providers/github/index.js'
import { signStripeWebhook, stripe } from '../src/providers/stripe/index.js'
import { createWebhookRequest } from '../src/testing/index.js'

const BODY = '{"hello":"world"}'

describe('toRawWebhook', () => {
  it('reads a Request without consuming it for the caller', async () => {
    const request = createWebhookRequest({ body: BODY, headers: { 'x-a': '1' } })
    const raw = await toRawWebhook(request)

    expect(raw.text()).toBe(BODY)
    expect(raw.method).toBe('POST')
    expect(raw.url).toContain('example.test')
    // The original must still be readable — frameworks often read it after us.
    expect(await request.text()).toBe(BODY)
  })

  it('accepts a string, a Uint8Array, and an ArrayBuffer identically', async () => {
    const bytes = new TextEncoder().encode(BODY)
    const forms = [BODY, bytes, bytes.buffer.slice(0)] as const

    for (const body of forms) {
      const raw = await toRawWebhook({ headers: {}, body })
      expect(raw.text()).toBe(BODY)
      expect(raw.body).toEqual(bytes)
    }
  })

  it('looks headers up case-insensitively', async () => {
    const raw = await toRawWebhook({ headers: { 'X-Mixed-Case': 'v' }, body: BODY })
    expect(raw.header('x-mixed-case')).toBe('v')
    expect(raw.header('X-MIXED-CASE')).toBe('v')
    expect(raw.header('absent')).toBeNull()
  })

  it('joins Node-style repeated headers with a comma', async () => {
    const raw = await toRawWebhook({ headers: { 'x-multi': ['a', 'b'] }, body: BODY })
    expect(raw.header('x-multi')).toBe('a, b')
  })

  it('drops undefined header values rather than sending "undefined"', async () => {
    const raw = await toRawWebhook({ headers: { 'x-gone': undefined }, body: BODY })
    expect(raw.header('x-gone')).toBeNull()
  })

  it('accepts a Headers instance directly', async () => {
    const raw = await toRawWebhook({ headers: new Headers({ 'x-h': '1' }), body: BODY })
    expect(raw.header('x-h')).toBe('1')
  })

  it('defaults the method to POST and leaves url undefined', async () => {
    const raw = await toRawWebhook({ headers: {}, body: BODY })
    expect(raw.method).toBe('POST')
    expect(raw.url).toBeUndefined()
  })

  it('passes an existing RawWebhook straight through', async () => {
    const first = await toRawWebhook({ headers: {}, body: BODY })
    expect(await toRawWebhook(first)).toBe(first)
  })

  it('parses JSON and caches the decoded text', async () => {
    const raw = await toRawWebhook({ headers: {}, body: BODY })
    expect(raw.json()).toEqual({ hello: 'world' })
    expect(raw.text()).toBe(raw.text())
  })

  it('raises PayloadParseError on a body that is not JSON', async () => {
    const raw = await toRawWebhook({ headers: {}, body: 'not json at all' })
    expect(() => raw.json()).toThrow(PayloadParseError)
  })

  it('preserves bytes exactly, including whitespace and unicode escaping', async () => {
    // Re-serializing would change these and break every signature.
    const fussy = '{ "a" : 1,\n  "b": "\\u00e9\\ud83c\\udf89" }'
    const raw = await toRawWebhook({ headers: {}, body: fussy })
    expect(raw.text()).toBe(fussy)
  })

  it('keeps an empty body verifiable', async () => {
    const raw = await toRawWebhook({ headers: {}, body: '' })
    expect(raw.body).toEqual(new Uint8Array(0))
    expect(raw.text()).toBe('')
  })
})

describe('WebhookRouter resolution', () => {
  const secret = 'whsec_router'
  const now = new Date('2026-08-20T12:00:00Z')

  const build = (resolve?: (r: Request) => string | undefined) =>
    new WebhookRouter({
      providers: { stripe: stripe({ secret }), github: github({ secret: 'gh' }) },
      now: () => now,
      ...(resolve ? { resolve } : {}),
    })

  const stripeRequest = async (url: string) => {
    const body = JSON.stringify({
      id: 'evt_r',
      object: 'event',
      type: 'charge.succeeded',
      created: Math.floor(now.getTime() / 1000),
      data: { object: {} },
    })
    return createWebhookRequest({
      body,
      url,
      headers: {
        'stripe-signature': await signStripeWebhook(body, secret, Math.floor(now.getTime() / 1000)),
      },
    })
  }

  it('ignores a trailing slash when resolving the slug', async () => {
    const response = await build().fetch(await stripeRequest('https://x.test/api/hooks/stripe/'))
    expect(response.status).toBe(200)
  })

  it('ignores a query string', async () => {
    const response = await build().fetch(await stripeRequest('https://x.test/hooks/stripe?a=1'))
    expect(response.status).toBe(200)
  })

  it('honours a custom resolver', async () => {
    const router = build((request) => new URL(request.url).searchParams.get('p') ?? undefined)
    const response = await router.fetch(await stripeRequest('https://x.test/anything?p=stripe'))
    expect(response.status).toBe(200)
  })

  it('404s when a custom resolver returns nothing', async () => {
    const router = build(() => undefined)
    const response = await router.fetch(await stripeRequest('https://x.test/hooks/stripe'))
    expect(response.status).toBe(404)
    expect(await response.json()).toMatchObject({ error: 'unknown_provider' })
  })

  it('exposes the per-provider handler', async () => {
    const router = build()
    expect(router.handler('stripe')?.provider.id).toBe('stripe')
    expect(router.handler('nope')).toBeUndefined()
  })

  it('process() reports an unknown provider without throwing', async () => {
    const result = await build().process('nope', await stripeRequest('https://x.test/h/nope'))
    expect(result.ok).toBe(false)
    expect(result.error?.code).toBe('unknown_provider')
  })

  it('routes a signed GitHub delivery to the github handler only', async () => {
    const seen: string[] = []
    const body = JSON.stringify({ ref: 'refs/heads/main' })
    const router = build().on('github', 'push', (event) => {
      seen.push(event.provider)
    })

    const response = await router.fetch(
      createWebhookRequest({
        body,
        url: 'https://x.test/api/hooks/github',
        headers: {
          'x-hub-signature-256': await signGitHubWebhook(body, 'gh'),
          'x-github-event': 'push',
          'x-github-delivery': 'd_1',
        },
      }),
    )

    expect(response.status).toBe(200)
    expect(seen).toEqual(['github'])
  })
})
