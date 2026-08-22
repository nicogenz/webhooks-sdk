import {
  ConfigurationError,
  MissingSignatureError,
  PayloadParseError,
  SignatureVerificationError,
} from '../../core/errors.js'
import type { VerifyContext, WebhookProvider } from '../../core/provider.js'
import { assertWithinTolerance, matchesAnyHmac, resolveSecrets } from '../../core/scheme.js'
import type { EventMap, RawWebhook, WebhookEvent } from '../../core/types.js'
import { verifyEd25519 } from '../../crypto/ed25519.js'
import { fromBase64, toBase64 } from '../../crypto/encoding.js'
import { hmac } from '../../crypto/hmac.js'

/**
 * The Standard Webhooks specification (standardwebhooks.com), as implemented by
 * Svix and every vendor built on it.
 *
 * One implementation covers Resend, Clerk, Polar, Dodo, OpenAI, Replicate,
 * Stytch, Loops, and Svix itself, because the scheme is genuinely identical —
 * only the header prefix and the field holding the event name differ.
 */

/** Spec-defined headers, plus the `svix-*` names that predate the spec. */
const ID_HEADERS = ['webhook-id', 'svix-id'] as const
const TIMESTAMP_HEADERS = ['webhook-timestamp', 'svix-timestamp'] as const
const SIGNATURE_HEADERS = ['webhook-signature', 'svix-signature'] as const

/** The spec's recommended replay window. */
export const STANDARD_WEBHOOKS_TOLERANCE = 300

const SECRET_PREFIX = 'whsec_'
const PUBLIC_KEY_PREFIX = 'whpk_'

export interface StandardWebhooksOptions {
  /**
   * The signing secret, `whsec_` followed by base64. Pass an array to accept
   * several during a rotation.
   *
   * Omit only when verifying asymmetric (`v1a`) signatures with `publicKey`.
   */
  secret?: string | string[]
  /**
   * Ed25519 public key(s), `whpk_` followed by base64, for the spec's
   * asymmetric `v1a` signatures.
   */
  publicKey?: string | string[]
  /** Replay window in seconds. Defaults to 300. */
  tolerance?: number
  /** Provider slug. Defaults to `standard-webhooks`. */
  id?: string
  /** Display name for error messages. */
  name?: string
  /**
   * Where the event name lives in the body. Defaults to `type`, which is what
   * most vendors use; Replicate uses `status`, Stytch uses `action`.
   */
  eventType?: string | ((payload: unknown) => string | undefined)
}

export interface StandardWebhooksEvents extends EventMap {
  [type: string]: unknown
}

function readHeader(raw: RawWebhook, names: readonly string[]): string | null {
  for (const name of names) {
    const value = raw.header(name)
    if (value) return value
  }
  return null
}

/**
 * Decodes a `whsec_`-prefixed secret to raw key bytes.
 *
 * The spec stores the key base64-encoded after the prefix, so signing the
 * literal string instead of the decoded bytes produces a digest that never
 * matches. Invalid base64 fails here rather than surfacing later as an
 * unexplainable signature mismatch.
 */
function decodeSecret(secret: string, provider: string): Uint8Array {
  const body = secret.startsWith(SECRET_PREFIX) ? secret.slice(SECRET_PREFIX.length) : secret
  const bytes = fromBase64(body)
  if (bytes.length === 0) {
    throw new ConfigurationError(
      'Standard Webhooks secret is not valid base64 after the "whsec_" prefix',
      { provider },
    )
  }
  return bytes
}

function decodePublicKey(key: string, provider: string): Uint8Array {
  const body = key.startsWith(PUBLIC_KEY_PREFIX) ? key.slice(PUBLIC_KEY_PREFIX.length) : key
  const bytes = fromBase64(body)
  if (bytes.length === 0) {
    throw new ConfigurationError(
      'Standard Webhooks public key is not valid base64 after the "whpk_" prefix',
      { provider },
    )
  }
  return bytes
}

export interface ParsedStandardSignature {
  /** Symmetric HMAC candidates, from `v1,` entries. */
  symmetric: string[]
  /** Asymmetric Ed25519 candidates, from `v1a,` entries. */
  asymmetric: string[]
}

/**
 * Parses `v1,base64sig v1,other v1a,ed25519sig`.
 *
 * Entries are space-delimited and versioned. Unknown versions are ignored
 * rather than rejected, so a future `v2` does not break a working endpoint —
 * it simply finds no candidate and fails closed.
 */
export function parseStandardSignatureHeader(header: string): ParsedStandardSignature {
  const symmetric: string[] = []
  const asymmetric: string[] = []

  for (const entry of header.split(' ')) {
    const index = entry.indexOf(',')
    if (index === -1) continue
    const version = entry.slice(0, index)
    const signature = entry.slice(index + 1)
    if (!signature) continue
    if (version === 'v1') symmetric.push(signature)
    else if (version === 'v1a') asymmetric.push(signature)
  }

  return { symmetric, asymmetric }
}

function toArray(value: string | string[] | undefined): string[] {
  if (!value) return []
  return (Array.isArray(value) ? value : [value]).filter(Boolean)
}

/** Verifies a Standard Webhooks signature. */
export async function verifyStandardWebhook(
  raw: RawWebhook,
  options: StandardWebhooksOptions,
  ctx?: Partial<VerifyContext>,
): Promise<void> {
  const provider = options.id ?? 'standard-webhooks'
  const publicKeys = toArray(options.publicKey)

  // Either credential alone is sufficient, so the empty check cannot be left
  // to resolveSecrets.
  if (toArray(options.secret).length === 0 && publicKeys.length === 0) {
    throw new ConfigurationError('No Standard Webhooks secret or public key was provided', {
      provider,
    })
  }

  const secrets =
    toArray(options.secret).length > 0
      ? resolveSecrets(options.secret, provider, (secret) => decodeSecret(secret, provider))
      : []

  const id = readHeader(raw, ID_HEADERS)
  const timestamp = readHeader(raw, TIMESTAMP_HEADERS)
  const signatureHeader = readHeader(raw, SIGNATURE_HEADERS)

  if (!id || !timestamp || !signatureHeader) {
    const missing = [
      !id && 'webhook-id',
      !timestamp && 'webhook-timestamp',
      !signatureHeader && 'webhook-signature',
    ].filter(Boolean)
    throw new MissingSignatureError(`Missing Standard Webhooks header(s): ${missing.join(', ')}`, {
      provider,
    })
  }

  const sentAt = Number.parseInt(timestamp, 10)
  if (Number.isNaN(sentAt)) {
    throw new MissingSignatureError(`webhook-timestamp is not an integer: "${timestamp}"`, {
      provider,
    })
  }

  assertWithinTolerance(
    sentAt,
    {
      now: ctx?.now ?? new Date(),
      tolerance: ctx?.tolerance ?? options.tolerance ?? STANDARD_WEBHOOKS_TOLERANCE,
    },
    provider,
  )

  // The id and timestamp are inside the signed material, which is what makes
  // this scheme replay-safe without an external store.
  const signedContent = `${id}.${sentAt}.${raw.text()}`
  const parsed = parseStandardSignatureHeader(signatureHeader)

  if (
    secrets.length > 0 &&
    (await matchesAnyHmac({
      secrets,
      content: signedContent,
      candidates: parsed.symmetric,
      encoding: 'base64',
    }))
  ) {
    return
  }

  for (const publicKey of publicKeys) {
    const key = decodePublicKey(publicKey, provider)
    for (const candidate of parsed.asymmetric) {
      if (await verifyEd25519(key, fromBase64(candidate), signedContent)) return
    }
  }

  throw new SignatureVerificationError('No Standard Webhooks signature matched the request', {
    provider,
  })
}

function resolveEventType(
  payload: unknown,
  eventType: StandardWebhooksOptions['eventType'],
): string | undefined {
  if (typeof eventType === 'function') return eventType(payload)
  const field = eventType ?? 'type'
  if (payload && typeof payload === 'object') {
    const value = (payload as Record<string, unknown>)[field]
    if (typeof value === 'string') return value
  }
  return undefined
}

/** Turns a verified Standard Webhooks request into a normalized event. */
export function parseStandardWebhook(
  raw: RawWebhook,
  options: StandardWebhooksOptions = {},
): WebhookEvent<string, unknown> {
  const provider = options.id ?? 'standard-webhooks'
  const payload = raw.json<unknown>()
  const type = resolveEventType(payload, options.eventType)

  if (!type) {
    const field = typeof options.eventType === 'string' ? options.eventType : 'type'
    throw new PayloadParseError(`Payload has no string "${field}" field to use as the event name`, {
      provider,
    })
  }

  // The spec makes webhook-id the canonical deduplication key, so prefer it
  // over anything in the body.
  const id = readHeader(raw, ID_HEADERS) ?? ''
  const timestamp = readHeader(raw, TIMESTAMP_HEADERS)
  const sentAt = timestamp ? Number.parseInt(timestamp, 10) : Number.NaN

  return {
    id,
    provider,
    type,
    timestamp: Number.isNaN(sentAt) ? new Date() : new Date(sentAt * 1000),
    payload,
    raw,
  }
}

/**
 * A provider for any Standard Webhooks vendor, including ones this SDK does
 * not wrap by name.
 *
 * ```ts
 * standardWebhooks({ id: 'acme', secret: process.env.ACME_SECRET! })
 * ```
 */
// Built by hand rather than with createHmacProvider: the spec's asymmetric
// v1a branch is a public-key verification, which the HMAC scheme description
// has no way to express. It still uses the same shared primitives underneath.
export function standardWebhooks<TEvents extends EventMap = StandardWebhooksEvents>(
  options: StandardWebhooksOptions,
): WebhookProvider<TEvents> {
  return {
    id: options.id ?? 'standard-webhooks',
    name: options.name ?? 'Standard Webhooks',
    tolerance: options.tolerance ?? STANDARD_WEBHOOKS_TOLERANCE,
    async verify(raw, ctx) {
      await verifyStandardWebhook(raw, options, ctx)
    },
    async parse(raw) {
      return parseStandardWebhook(raw, options)
    },
  }
}

export interface SignedStandardWebhook {
  'webhook-id': string
  'webhook-timestamp': string
  'webhook-signature': string
}

/**
 * Produces valid Standard Webhooks headers for a body. For tests and local
 * replay.
 *
 * Pass `headerPrefix: 'svix'` to emit the legacy `svix-*` names instead.
 */
export async function signStandardWebhook(
  body: string,
  secret: string,
  options: { id?: string; timestamp?: number; headerPrefix?: 'webhook' | 'svix' } = {},
): Promise<Record<string, string>> {
  const id = options.id ?? 'msg_test'
  const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000)
  const key = decodeSecret(secret, 'standard-webhooks')
  const signature = toBase64(await hmac('SHA-256', key, `${id}.${timestamp}.${body}`))
  const prefix = options.headerPrefix ?? 'webhook'

  return {
    [`${prefix}-id`]: id,
    [`${prefix}-timestamp`]: String(timestamp),
    [`${prefix}-signature`]: `v1,${signature}`,
  }
}
