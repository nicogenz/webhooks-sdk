import { describe, expect, it } from 'vitest'
import {
  ConfigurationError,
  DuplicateEventError,
  HandlerError,
  isWebhookError,
  KeyUnavailableError,
  MissingSignatureError,
  PayloadParseError,
  SignatureVerificationError,
  TimestampToleranceError,
  toRawWebhook,
  UnknownProviderError,
  verifyEd25519,
  WebhookError,
} from '../src/index.js'
import {
  parseGitHubWebhook,
  signGitHubWebhook,
  verifyGitHubWebhook,
} from '../src/providers/github/index.js'
import { verifyStandardWebhook } from '../src/providers/standard-webhooks/index.js'
import {
  parseStripeWebhook,
  signStripeWebhook,
  verifyStripeWebhook,
} from '../src/providers/stripe/index.js'

const NOW = new Date('2026-08-20T12:00:00Z')
const TS = Math.floor(NOW.getTime() / 1000)

describe('error taxonomy', () => {
  // These codes and statuses are what callers branch on, so they are API.
  it.each([
    [new MissingSignatureError('m'), 'missing_signature', 400, true],
    [new SignatureVerificationError('m'), 'invalid_signature', 401, true],
    [new TimestampToleranceError('m'), 'timestamp_out_of_tolerance', 400, true],
    [new PayloadParseError('m'), 'invalid_payload', 400, false],
    [new ConfigurationError('m'), 'invalid_configuration', 500, false],
    // 500 and not a verification failure: an unreachable JWKS is an outage on
    // our side, not evidence about the request.
    [new KeyUnavailableError('m'), 'key_unavailable', 500, false],
    [new DuplicateEventError('m'), 'duplicate_event', 200, false],
    [new UnknownProviderError('m'), 'unknown_provider', 404, false],
    [new HandlerError('m'), 'handler_failed', 500, false],
  ])('%#: maps code, status, and verification-failure flag', (error, code, status, isFailure) => {
    expect(error.code).toBe(code)
    expect(error.status).toBe(status)
    expect(error.isVerificationFailure).toBe(isFailure)
    expect(isWebhookError(error)).toBe(true)
  })

  it('allows a status override and carries the provider through', () => {
    const error = new SignatureVerificationError('m', { provider: 'acme', status: 418 })
    expect(error.status).toBe(418)
    expect(error.toJSON()).toEqual({ error: 'invalid_signature', message: 'm', provider: 'acme' })
  })

  it('preserves the cause and names itself after the subclass', () => {
    const cause = new Error('root')
    const error = new PayloadParseError('m', { cause })
    expect(error.cause).toBe(cause)
    expect(error.name).toBe('PayloadParseError')
    expect(error instanceof WebhookError).toBe(true)
  })

  it('rejects non-errors', () => {
    expect(isWebhookError(new Error('plain'))).toBe(false)
    expect(isWebhookError('invalid_signature')).toBe(false)
    expect(isWebhookError(null)).toBe(false)
  })
})

describe('standalone verification', () => {
  // The README documents these as the escape hatch for callers who do not want
  // the handler, so they need coverage independent of it.
  const secret = 'whsec_standalone'
  const event = {
    id: 'evt_s',
    object: 'event' as const,
    type: 'invoice.paid',
    created: TS,
    data: { object: {} },
  }
  const body = JSON.stringify(event)

  it('verifyStripeWebhook resolves on a good signature and throws on a bad one', async () => {
    const raw = await toRawWebhook({
      headers: { 'stripe-signature': await signStripeWebhook(body, secret, TS) },
      body,
    })

    await expect(verifyStripeWebhook(raw, { secret }, { now: NOW })).resolves.toBeUndefined()
    await expect(verifyStripeWebhook(raw, { secret: 'nope' }, { now: NOW })).rejects.toThrow(
      SignatureVerificationError,
    )
  })

  it('verifyStripeWebhook honours an explicit tolerance override', async () => {
    const stale = TS - 3600
    const raw = await toRawWebhook({
      headers: { 'stripe-signature': await signStripeWebhook(body, secret, stale) },
      body,
    })

    await expect(verifyStripeWebhook(raw, { secret }, { now: NOW })).rejects.toThrow(
      TimestampToleranceError,
    )
    // 0 disables the window entirely.
    await expect(
      verifyStripeWebhook(raw, { secret }, { now: NOW, tolerance: 0 }),
    ).resolves.toBeUndefined()
  })

  it('parseStripeWebhook rejects a payload missing id or type', async () => {
    const raw = await toRawWebhook({ headers: {}, body: JSON.stringify({ data: {} }) })
    expect(() => parseStripeWebhook(raw)).toThrow(PayloadParseError)
  })

  it('verifyGitHubWebhook works without a handler', async () => {
    const payload = JSON.stringify({ ref: 'refs/heads/main' })
    const raw = await toRawWebhook({
      headers: {
        'x-hub-signature-256': await signGitHubWebhook(payload, 'gh'),
        'x-github-event': 'push',
        'x-github-delivery': 'd_1',
      },
      body: payload,
    })

    await expect(verifyGitHubWebhook(raw, { secret: 'gh' })).resolves.toBeUndefined()
    await expect(verifyGitHubWebhook(raw, { secret: 'other' })).rejects.toThrow(
      SignatureVerificationError,
    )
    expect((await parseGitHubWebhook(raw)).type).toBe('push')
  })

  it('parseGitHubWebhook rejects a request missing the delivery header', async () => {
    const payload = JSON.stringify({ ref: 'refs/heads/main' })
    const raw = await toRawWebhook({ headers: { 'x-github-event': 'push' }, body: payload })
    await expect(parseGitHubWebhook(raw)).rejects.toThrow(PayloadParseError)
  })

  it('verifyStandardWebhook works without a handler', async () => {
    const raw = await toRawWebhook({ headers: {}, body: '{}' })
    await expect(verifyStandardWebhook(raw, { secret: 'whsec_YWJj' })).rejects.toThrow(
      MissingSignatureError,
    )
  })
})

describe('verifyEd25519', () => {
  it('returns false rather than throwing on malformed key material', async () => {
    // Import failure must not crash the request path.
    expect(await verifyEd25519(new Uint8Array(3), new Uint8Array(64), 'msg')).toBe(false)
    expect(await verifyEd25519(new Uint8Array(0), new Uint8Array(0), '')).toBe(false)
  })

  it('returns false for a well-formed key with a wrong signature', async () => {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
    expect(await verifyEd25519(raw, new Uint8Array(64), 'msg')).toBe(false)
  })
})
