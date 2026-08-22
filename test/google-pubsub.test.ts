import { beforeAll, describe, expect, it, vi } from 'vitest'
import { toBase64, toBase64Url, utf8 } from '../src/crypto/index.js'
import type { Jwk } from '../src/index.js'
import { createRemoteKeySet, createWebhookHandler, toRawWebhook } from '../src/index.js'
import type { GooglePubSubEventPayload } from '../src/providers/google-pubsub/index.js'
import {
  googlePubSub,
  parseGooglePubSubWebhook,
  signGooglePubSubWebhook,
} from '../src/providers/google-pubsub/index.js'
import { createWebhookRequest } from '../src/testing/index.js'

const NOW = new Date('2026-08-20T12:00:00Z')
const TS = Math.floor(NOW.getTime() / 1000)
const AUDIENCE = 'https://example.com/webhooks/pubsub'
const EMAIL = 'push@my-project.iam.gserviceaccount.com'

const INNER = { emailAddress: 'user@example.com', historyId: 421 }
const ENVELOPE = {
  message: {
    data: toBase64(utf8(JSON.stringify(INNER))),
    attributes: { eventType: 'history.updated' },
    messageId: '2070443601311540',
    publishTime: '2026-08-20T11:59:00.000Z',
  },
  subscription: 'projects/my-project/subscriptions/my-subscription',
}

const RSA_PARAMS = {
  name: 'RSASSA-PKCS1-v1_5',
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: 'SHA-256',
}

let keys: CryptoKeyPair
let otherKeys: CryptoKeyPair
let jwk: Jwk

beforeAll(async () => {
  keys = (await crypto.subtle.generateKey(RSA_PARAMS, true, ['sign', 'verify'])) as CryptoKeyPair
  otherKeys = (await crypto.subtle.generateKey(RSA_PARAMS, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair
  jwk = { ...(await crypto.subtle.exportKey('jwk', keys.publicKey)), kid: 'test-key' }
})

async function signed(
  overrides: {
    key?: CryptoKey
    body?: object | string
    audience?: string
    kid?: string
    email?: string
    emailVerified?: boolean
    issuer?: string
    issuedAt?: number
    expiresAt?: number
  } = {},
) {
  const headers = await signGooglePubSubWebhook(overrides.key ?? keys.privateKey, {
    audience: overrides.audience ?? AUDIENCE,
    kid: overrides.kid,
    email: overrides.email ?? EMAIL,
    emailVerified: overrides.emailVerified,
    issuer: overrides.issuer,
    issuedAt: overrides.issuedAt ?? TS - 60,
    expiresAt: overrides.expiresAt,
  })
  return createWebhookRequest({ body: overrides.body ?? ENVELOPE, headers })
}

type ProviderOptions = Partial<Parameters<typeof googlePubSub>[0]>

const handlerFor = (overrides: ProviderOptions = {}) =>
  createWebhookHandler({
    provider: googlePubSub({
      audience: AUDIENCE,
      serviceAccountEmail: EMAIL,
      keys: [jwk],
      ...overrides,
    }),
    now: () => NOW,
  })

describe('google pub/sub verification', () => {
  it('accepts a valid OIDC token and unwraps the envelope', async () => {
    const result = await handlerFor().process(await signed())
    expect(result.ok).toBe(true)
    expect(result.event?.id).toBe('2070443601311540')
    expect(result.event?.type).toBe('message')
    expect(result.event?.timestamp).toEqual(new Date('2026-08-20T11:59:00.000Z'))

    const payload = result.event?.payload as GooglePubSubEventPayload
    expect(payload.subscription).toBe('projects/my-project/subscriptions/my-subscription')
    expect(payload.message.attributes.eventType).toBe('history.updated')
    expect(payload.message.json()).toEqual(INNER)
  })

  it('rejects a token signed by a different key', async () => {
    const result = await handlerFor().process(await signed({ key: otherKeys.privateKey }))
    expect(result.error?.code).toBe('invalid_signature')
    expect(result.error?.status).toBe(401)
  })

  it('rejects a token naming an unknown kid', async () => {
    const result = await handlerFor().process(await signed({ kid: 'rotated-away' }))
    expect(result.error?.code).toBe('invalid_signature')
  })

  it('rejects a token minted for a different audience', async () => {
    const result = await handlerFor().process(
      await signed({ audience: 'https://other.example.com/hook' }),
    )
    expect(result.error?.code).toBe('invalid_signature')
  })

  it('accepts any of several configured audiences', async () => {
    const handler = handlerFor({ audience: ['https://a.example.com', AUDIENCE] })
    expect((await handler.process(await signed())).ok).toBe(true)
  })

  it('rejects a non-Google issuer', async () => {
    const result = await handlerFor().process(await signed({ issuer: 'https://evil.example.com' }))
    expect(result.error?.code).toBe('invalid_signature')
  })

  it('accepts the bare accounts.google.com issuer spelling', async () => {
    const result = await handlerFor().process(await signed({ issuer: 'accounts.google.com' }))
    expect(result.ok).toBe(true)
  })

  it('rejects an expired token beyond the clock skew, accepts one inside it', async () => {
    const expired = await handlerFor().process(await signed({ expiresAt: TS - 400 }))
    expect(expired.error?.code).toBe('timestamp_out_of_tolerance')

    const inSkew = await handlerFor().process(await signed({ expiresAt: TS - 100 }))
    expect(inSkew.ok).toBe(true)
  })

  it('rejects a token issued in the future beyond the skew', async () => {
    const result = await handlerFor().process(
      await signed({ issuedAt: TS + 3600, expiresAt: TS + 7200 }),
    )
    expect(result.error?.code).toBe('timestamp_out_of_tolerance')
  })

  it('enforces the service account email', async () => {
    const guarded = handlerFor()
    expect((await guarded.process(await signed())).ok).toBe(true)

    const wrong = await guarded.process(await signed({ email: 'other@example.com' }))
    expect(wrong.error?.code).toBe('invalid_signature')

    const unverified = await guarded.process(await signed({ emailVerified: false }))
    expect(unverified.error?.code).toBe('invalid_signature')
  })

  it('rejects a configuration that names no service account email', async () => {
    // Anyone can point their own push subscription at this endpoint and have
    // Google mint a valid token for it, so verifying without an expected
    // email would be fail-open. The cast simulates a JS caller omitting it.
    const options = { audience: AUDIENCE, keys: [jwk] } as Parameters<typeof googlePubSub>[0]
    const handler = createWebhookHandler({ provider: googlePubSub(options), now: () => NOW })
    const result = await handler.process(await signed())
    expect(result.error?.code).toBe('invalid_configuration')
  })

  it('rejects a request with no Authorization header', async () => {
    const result = await handlerFor().process(createWebhookRequest({ body: ENVELOPE }))
    expect(result.error?.code).toBe('missing_signature')
  })

  it('rejects a malformed bearer token', async () => {
    const result = await handlerFor().process(
      createWebhookRequest({ body: ENVELOPE, headers: { authorization: 'Bearer not.a.jwt' } }),
    )
    expect(result.error?.code).toBe('missing_signature')
  })

  it('rejects any algorithm other than RS256', async () => {
    // Hand-rolled alg:none token — the classic downgrade probe.
    const header = toBase64Url(utf8(JSON.stringify({ alg: 'none', kid: 'test-key' })))
    const claims = toBase64Url(
      utf8(JSON.stringify({ iss: 'https://accounts.google.com', aud: AUDIENCE, exp: TS + 3600 })),
    )
    const result = await handlerFor().process(
      createWebhookRequest({
        body: ENVELOPE,
        headers: { authorization: `Bearer ${header}.${claims}.${toBase64Url(utf8('sig'))}` },
      }),
    )
    expect(result.error?.code).toBe('invalid_signature')
  })
})

describe('google pub/sub remote key set', () => {
  const jwks = (webKeys: Jwk[]) =>
    new Response(JSON.stringify({ keys: webKeys }), {
      headers: { 'content-type': 'application/json' },
    })

  it('fetches the JWKS once and serves later verifications from cache', async () => {
    const fetchMock = vi.fn(async () => jwks([jwk]))
    const handler = handlerFor({ keys: undefined, fetch: fetchMock })

    expect((await handler.process(await signed())).ok).toBe(true)
    expect((await handler.process(await signed())).ok).toBe(true)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('refetches when an unknown kid arrives — a rotation, not a miss', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jwks([{ ...jwk, kid: 'old-key' }]))
      .mockResolvedValueOnce(jwks([{ ...jwk, kid: 'rotated-key' }]))

    // One provider, two points in time: the cache is still fresh when the
    // rotated kid arrives, but the refresh cooldown has passed.
    const provider = googlePubSub({
      audience: AUDIENCE,
      serviceAccountEmail: EMAIL,
      fetch: fetchMock,
    })
    const before = createWebhookHandler({ provider, now: () => NOW })
    const after = createWebhookHandler({
      provider,
      now: () => new Date(NOW.getTime() + 120_000),
    })

    expect((await before.process(await signed({ kid: 'old-key' }))).ok).toBe(true)
    expect((await after.process(await signed({ kid: 'rotated-key' }))).ok).toBe(true)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('reports an unreachable JWKS as key_unavailable, not as a bad signature', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new TypeError('fetch failed'))
    const result = await handlerFor({ keys: undefined, fetch: fetchMock }).process(await signed())
    expect(result.error?.code).toBe('key_unavailable')
    expect(result.error?.status).toBe(500)
    expect(result.error?.isVerificationFailure).toBe(false)
  })

  it('falls back to previously fetched keys when a refresh fails', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jwks([jwk]))
      .mockRejectedValue(new TypeError('fetch failed'))

    const keySet = createRemoteKeySet({ url: 'https://example.com/jwks', fetch: fetchMock })
    expect(await keySet.get('test-key', NOW)).toBeDefined()

    // Two hours later the cache is past its TTL and the refresh fails; stale
    // Google keys still beat failing every delivery.
    const later = new Date(NOW.getTime() + 2 * 3600_000)
    expect(await keySet.get('test-key', later)).toBeDefined()
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('honours Cache-Control max-age over the default TTL', async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify({ keys: [jwk] }), {
          headers: { 'cache-control': 'public, max-age=30' },
        }),
    )
    const keySet = createRemoteKeySet({ url: 'https://example.com/jwks', fetch: fetchMock })

    await keySet.get('test-key', NOW)
    await keySet.get('test-key', new Date(NOW.getTime() + 10_000))
    expect(fetchMock).toHaveBeenCalledTimes(1)

    await keySet.get('test-key', new Date(NOW.getTime() + 40_000))
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})

describe('google pub/sub parsing', () => {
  it('accepts the snake_case field spellings Google also sends', async () => {
    const raw = await toRawWebhook({
      headers: {},
      body: JSON.stringify({
        message: { data: '', message_id: 'm1', publish_time: '2026-08-20T11:00:00Z' },
        subscription: 'projects/p/subscriptions/s',
      }),
    })
    const event = parseGooglePubSubWebhook(raw)
    expect(event.id).toBe('m1')
    expect(event.timestamp).toEqual(new Date('2026-08-20T11:00:00Z'))
  })

  it('rejects a body with no message id', async () => {
    const result = await handlerFor().process(await signed({ body: { subscription: 's' } }))
    expect(result.error?.code).toBe('invalid_payload')
  })

  it('reports non-JSON message data only when json() is asked for', async () => {
    const body = {
      message: { data: toBase64(utf8('plain bytes')), messageId: 'm2' },
      subscription: 's',
    }
    const result = await handlerFor().process(await signed({ body }))
    expect(result.ok).toBe(true)

    const payload = result.event?.payload as GooglePubSubEventPayload
    expect(payload.message.text()).toBe('plain bytes')
    expect(() => payload.message.json()).toThrow('not valid JSON')
  })

  it('derives the event name from an attribute when asked to', async () => {
    const result = await handlerFor({ eventType: 'eventType' }).process(await signed())
    expect(result.event?.type).toBe('history.updated')
  })

  it('derives the event name through a function, falling back to message', async () => {
    const handler = handlerFor({
      eventType: (payload) => payload.message.attributes.missing,
    })
    const result = await handler.process(await signed())
    expect(result.event?.type).toBe('message')
  })
})
