import { MissingSignatureError, PayloadParseError } from '../../core/errors.js'
import type { VerifyContext, WebhookProvider } from '../../core/provider.js'
import type { HmacProviderConfig, SignatureMaterial } from '../../core/scheme.js'
import { createHmacProvider, verifyWithScheme } from '../../core/scheme.js'
import type { EventMap, RawWebhook, WebhookEvent } from '../../core/types.js'
import { hmacHex } from '../../crypto/hmac.js'

export const STRIPE_SIGNATURE_HEADER = 'stripe-signature'

/** Stripe's own default replay window. */
export const STRIPE_DEFAULT_TOLERANCE = 300

export interface StripeOptions {
  /**
   * The endpoint signing secret (`whsec_...`). Pass an array to accept several
   * during a rotation — Stripe keeps the old secret valid for 24 hours after
   * you roll it.
   */
  secret: string | string[]
  /** Replay window in seconds. Defaults to 300. */
  tolerance?: number
}

/** The shape Stripe puts on the wire. `data.object` stays untyped by design. */
export interface StripeEventPayload {
  id: string
  object: 'event'
  type: string
  created: number
  api_version: string | null
  livemode: boolean
  data: { object: unknown; previous_attributes?: unknown }
  request?: { id: string | null; idempotency_key: string | null } | null
  pending_webhooks?: number
}

/**
 * A non-exhaustive set of common event names, for autocomplete. Any string is
 * still accepted — Stripe adds event types continuously.
 */
export interface StripeEvents extends EventMap {
  'payment_intent.succeeded': StripeEventPayload
  'payment_intent.payment_failed': StripeEventPayload
  'charge.succeeded': StripeEventPayload
  'charge.refunded': StripeEventPayload
  'charge.dispute.created': StripeEventPayload
  'checkout.session.completed': StripeEventPayload
  'checkout.session.expired': StripeEventPayload
  'customer.created': StripeEventPayload
  'customer.subscription.created': StripeEventPayload
  'customer.subscription.updated': StripeEventPayload
  'customer.subscription.deleted': StripeEventPayload
  'customer.subscription.trial_will_end': StripeEventPayload
  'invoice.paid': StripeEventPayload
  'invoice.payment_failed': StripeEventPayload
  'invoice.finalized': StripeEventPayload
  'payout.paid': StripeEventPayload
  'payout.failed': StripeEventPayload
}

interface ParsedSignature {
  timestamp: number
  signatures: string[]
}

/**
 * Parses `t=1614556800,v1=abc,v1=def`.
 *
 * Multiple `v1` entries appear while an endpoint has more than one active
 * secret, so any match is enough.
 */
export function parseStripeSignatureHeader(header: string): ParsedSignature | null {
  let timestamp = Number.NaN
  const signatures: string[] = []

  for (const part of header.split(',')) {
    const index = part.indexOf('=')
    if (index === -1) continue
    const key = part.slice(0, index).trim()
    const value = part.slice(index + 1).trim()
    if (key === 't') timestamp = Number.parseInt(value, 10)
    else if (key === 'v1') signatures.push(value)
  }

  if (Number.isNaN(timestamp) || signatures.length === 0) return null
  return { timestamp, signatures }
}

function extract(raw: RawWebhook): SignatureMaterial {
  const header = raw.header(STRIPE_SIGNATURE_HEADER)
  if (!header) {
    throw new MissingSignatureError(`Missing ${STRIPE_SIGNATURE_HEADER} header`, {
      provider: 'stripe',
    })
  }

  const parsed = parseStripeSignatureHeader(header)
  if (!parsed) {
    throw new MissingSignatureError(`Malformed ${STRIPE_SIGNATURE_HEADER} header`, {
      provider: 'stripe',
    })
  }

  return { candidates: parsed.signatures, timestamp: parsed.timestamp }
}

/** Turns a verified Stripe request into a normalized event. */
export function parseStripeWebhook(raw: RawWebhook): WebhookEvent<string, StripeEventPayload> {
  const payload = raw.json<StripeEventPayload>()
  if (!payload || typeof payload.type !== 'string' || typeof payload.id !== 'string') {
    throw new PayloadParseError('Stripe payload is missing `id` or `type`', { provider: 'stripe' })
  }

  return {
    id: payload.id,
    provider: 'stripe',
    type: payload.type,
    timestamp: new Date((payload.created ?? 0) * 1000),
    payload,
    raw,
  }
}

/**
 * Stripe signs `${timestamp}.${rawBody}` with HMAC-SHA256 and hex-encodes it.
 * The timestamp is inside the signed material, so an attacker cannot replay an
 * old body under a fresh timestamp.
 */
function schemeFor(options: StripeOptions): HmacProviderConfig {
  return {
    id: 'stripe',
    name: 'Stripe',
    secret: options.secret,
    encoding: 'hex',
    tolerance: options.tolerance ?? STRIPE_DEFAULT_TOLERANCE,
    extract,
    content: (material, raw) => `${material.timestamp}.${raw.text()}`,
    event: parseStripeWebhook,
  }
}

/** Verifies a Stripe webhook signature. */
export async function verifyStripeWebhook(
  raw: RawWebhook,
  options: StripeOptions,
  ctx?: Partial<VerifyContext>,
): Promise<void> {
  await verifyWithScheme(raw, schemeFor(options), ctx)
}

/** The Stripe integration. */
export function stripe(options: StripeOptions): WebhookProvider<StripeEvents> {
  return createHmacProvider<StripeEvents>(schemeFor(options))
}

/**
 * Produces a valid `Stripe-Signature` header for a body. For tests and local
 * replay — never for signing traffic you send to someone else.
 */
export async function signStripeWebhook(
  body: string,
  secret: string,
  timestamp: number = Math.floor(Date.now() / 1000),
): Promise<string> {
  const signature = await hmacHex('SHA-256', secret, `${timestamp}.${body}`)
  return `t=${timestamp},v1=${signature}`
}
