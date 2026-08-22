import { timingSafeEqualBase64, timingSafeEqualHex, utf8 } from '../crypto/encoding.js'
import type { HashAlgorithm } from '../crypto/hmac.js'
import { hmacBase64, hmacHex } from '../crypto/hmac.js'
import {
  ConfigurationError,
  SignatureVerificationError,
  TimestampToleranceError,
} from './errors.js'
import type { VerifyContext, WebhookProvider } from './provider.js'
import type { EventMap, RawWebhook, WebhookEvent } from './types.js'

/**
 * Machinery for building HMAC-based providers.
 *
 * Signature families 1, 2, and 3 in INTEGRATIONS.md look like three schemes but
 * are one algorithm with four parameters: which headers carry the signature,
 * how the digest is encoded, what string was signed, and how the secret is
 * decoded. Everything else — the replay window, accepting several secrets
 * during a rotation, accepting several candidate signatures, comparing in
 * constant time — is identical, and duplicating it per provider is how the
 * details drift apart.
 */

/** What a provider pulls out of the request before it can verify anything. */
export interface SignatureMaterial {
  /** Candidate signatures. More than one appears during key rotation. */
  candidates: string[]
  /** Unix seconds, when the scheme signs a timestamp. */
  timestamp?: number
  /** Message id, when the scheme signs one. */
  id?: string
}

export type SignatureEncoding = 'hex' | 'base64'

/**
 * Turns configured secrets into key bytes, rejecting an empty set.
 *
 * `decode` exists because Standard Webhooks stores the key base64-encoded after
 * a `whsec_` prefix, while most providers use the literal string.
 */
export function resolveSecrets(
  secret: string | string[] | undefined,
  provider: string,
  decode: (secret: string) => Uint8Array = utf8,
): Uint8Array[] {
  const values = (secret === undefined ? [] : Array.isArray(secret) ? secret : [secret]).filter(
    Boolean,
  )
  if (values.length === 0) {
    throw new ConfigurationError(`No signing secret was provided for ${provider}`, { provider })
  }
  return values.map(decode)
}

/** Enforces the replay window. A tolerance of 0 disables the check. */
export function assertWithinTolerance(
  timestamp: number,
  ctx: Pick<VerifyContext, 'now' | 'tolerance'>,
  provider: string,
): void {
  if (!ctx.tolerance || ctx.tolerance <= 0) return
  if (!Number.isFinite(timestamp)) {
    throw new TimestampToleranceError(`Timestamp is not a finite number: ${timestamp}`, {
      provider,
    })
  }
  const age = Math.abs(Math.floor(ctx.now.getTime() / 1000) - timestamp)
  if (age > ctx.tolerance) {
    throw new TimestampToleranceError(
      `Timestamp is ${age}s away from now, outside the ${ctx.tolerance}s tolerance`,
      { provider },
    )
  }
}

export interface HmacMatchOptions {
  secrets: readonly Uint8Array[]
  content: string
  candidates: readonly string[]
  algorithm?: HashAlgorithm
  encoding: SignatureEncoding
}

/**
 * True when any secret produces a digest matching any candidate.
 *
 * Both loops run to completion rather than short-circuiting on the first
 * mismatch, so the number of configured secrets is not observable through
 * response timing.
 */
export async function matchesAnyHmac(options: HmacMatchOptions): Promise<boolean> {
  const { secrets, content, candidates, algorithm = 'SHA-256', encoding } = options
  const digest = encoding === 'hex' ? hmacHex : hmacBase64
  const equal = encoding === 'hex' ? timingSafeEqualHex : timingSafeEqualBase64

  let matched = false
  for (const secret of secrets) {
    const expected = await digest(algorithm, secret, content)
    for (const candidate of candidates) {
      if (equal(expected, candidate)) matched = true
    }
  }
  return matched
}

export interface HmacProviderConfig {
  /** Stable slug used in routes, logs, and idempotency keys. */
  id: string
  /** Human-readable name for error messages. */
  name: string
  secret: string | string[] | undefined
  encoding: SignatureEncoding
  algorithm?: HashAlgorithm
  /** Replay window in seconds. Omit or 0 when the scheme signs no timestamp. */
  tolerance?: number
  /** Defaults to the literal secret bytes. */
  decodeSecret?: (secret: string) => Uint8Array
  /** Reads the signature headers. Throws `MissingSignatureError` if absent. */
  extract: (raw: RawWebhook) => SignatureMaterial
  /**
   * Rebuilds the exact string the provider signed. May be async — Twilio's
   * JSON flow folds a SHA-256 of the body into the signed URL, and Web Crypto
   * digests are Promise-based.
   */
  content: (material: SignatureMaterial, raw: RawWebhook) => string | Promise<string>
  /** Builds the normalized event from a verified request. May be async. */
  event: (raw: RawWebhook) => WebhookEvent<string, unknown> | Promise<WebhookEvent<string, unknown>>
}

/**
 * Builds a provider from an HMAC scheme description.
 *
 * ```ts
 * createHmacProvider({
 *   id: 'acme',
 *   name: 'Acme',
 *   secret,
 *   encoding: 'hex',
 *   extract: (raw) => ({ candidates: [required(raw, 'x-acme-signature')] }),
 *   content: (_material, raw) => raw.text(),
 *   event: parseAcmeWebhook,
 * })
 * ```
 */
export function createHmacProvider<TEvents extends EventMap = EventMap>(
  config: HmacProviderConfig,
): WebhookProvider<TEvents> {
  return {
    id: config.id,
    name: config.name,
    tolerance: config.tolerance ?? 0,

    async verify(raw, ctx) {
      const secrets = resolveSecrets(config.secret, config.id, config.decodeSecret)
      const material = config.extract(raw)

      if (material.timestamp !== undefined) {
        assertWithinTolerance(
          material.timestamp,
          { now: ctx.now, tolerance: ctx.tolerance ?? config.tolerance ?? 0 },
          config.id,
        )
      }

      const matched = await matchesAnyHmac({
        secrets,
        content: await config.content(material, raw),
        candidates: material.candidates,
        algorithm: config.algorithm,
        encoding: config.encoding,
      })

      if (!matched) {
        throw new SignatureVerificationError(
          `${config.name} signature does not match the request body`,
          { provider: config.id },
        )
      }
    },

    async parse(raw) {
      return config.event(raw)
    },
  }
}

/** Standalone verification for a scheme, without constructing a handler. */
export async function verifyWithScheme(
  raw: RawWebhook,
  config: HmacProviderConfig,
  ctx?: Partial<VerifyContext>,
): Promise<void> {
  await createHmacProvider(config).verify(raw, {
    now: ctx?.now ?? new Date(),
    tolerance: ctx?.tolerance ?? config.tolerance ?? 0,
  })
}
