/**
 * webhooks-sdk — one way to verify, parse, and route webhooks from every
 * provider.
 *
 * ```ts
 * import { createWebhookHandler } from 'webhooks-sdk'
 * import { stripe } from 'webhooks-sdk/stripe'
 *
 * const handler = createWebhookHandler({
 *   provider: stripe({ secret: process.env.STRIPE_WEBHOOK_SECRET! }),
 *   on: {
 *     'payment_intent.succeeded': async (event) => {
 *       await fulfill(event.payload.data.object)
 *     },
 *   },
 * })
 *
 * export const POST = handler.fetch
 * ```
 *
 * Providers live behind their own subpath (`webhooks-sdk/stripe`) so only the
 * ones you import end up in your bundle.
 */

export type { WebhookErrorCode, WebhookErrorOptions } from './core/errors.js'
export {
  ConfigurationError,
  DuplicateEventError,
  HandlerError,
  isWebhookError,
  KeyUnavailableError,
  MissingSignatureError,
  PayloadParseError,
  SignatureVerificationError,
  TimestampToleranceError,
  UnknownProviderError,
  WebhookError,
} from './core/errors.js'
export type {
  WebhookHandler,
  WebhookHandlerOptions,
  WebhookResult,
} from './core/handler.js'
export { createWebhookHandler, DEFAULT_TOLERANCE_SECONDS, toResponse } from './core/handler.js'
export type { IdempotencyStore, MemoryIdempotencyOptions } from './core/idempotency.js'
export { memoryIdempotencyStore } from './core/idempotency.js'
export type { Jwk, KeySet, RemoteKeySetOptions } from './core/keyset.js'
/**
 * Key material for the JWT and certificate families (5 and 6), which verify
 * against keys the provider rotates and the SDK has to fetch. The cache is
 * pluggable; `KeySet` is one method.
 */
export { createRemoteKeySet, staticKeySet } from './core/keyset.js'
export type { EventsOf, VerifyContext, WebhookProvider } from './core/provider.js'
export { toRawWebhook } from './core/request.js'
export type { WebhookRouterOptions } from './core/router.js'
export { WebhookRouter } from './core/router.js'
export type {
  HmacMatchOptions,
  HmacProviderConfig,
  SignatureEncoding,
  SignatureMaterial,
} from './core/scheme.js'
/**
 * Scheme machinery for building providers. Families 1, 2, and 3 in
 * INTEGRATIONS.md are one algorithm with four parameters, so a new HMAC-based
 * integration is usually a description rather than an implementation.
 */
export {
  assertWithinTolerance,
  createHmacProvider,
  matchesAnyHmac,
  resolveSecrets,
  verifyWithScheme,
} from './core/scheme.js'
export type {
  EventHandler,
  EventHandlers,
  EventMap,
  EventName,
  PayloadOf,
  RawWebhook,
  WebhookEvent,
  WebhookInput,
  WebhookOutcome,
} from './core/types.js'
export type { DecodedJwt, DigestAlgorithm, HashAlgorithm, SecretInput } from './crypto/index.js'
/**
 * Signature primitives, exported so a custom provider can be written without
 * reaching for a crypto library.
 */
export {
  decodeJwt,
  digest,
  digestHex,
  fromBase64,
  fromHex,
  fromUtf8,
  hmac,
  hmacBase64,
  hmacHex,
  timingSafeEqual,
  timingSafeEqualBase64,
  timingSafeEqualHex,
  timingSafeEqualString,
  toBase64,
  toBase64Url,
  toBytes,
  toHex,
  utf8,
  verifyEd25519,
  verifyJwtSignature,
} from './crypto/index.js'
