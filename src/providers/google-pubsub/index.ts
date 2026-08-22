import {
  ConfigurationError,
  MissingSignatureError,
  PayloadParseError,
  SignatureVerificationError,
  TimestampToleranceError,
} from '../../core/errors.js'
import type { Jwk, KeySet } from '../../core/keyset.js'
import { createRemoteKeySet, staticKeySet } from '../../core/keyset.js'
import type { VerifyContext, WebhookProvider } from '../../core/provider.js'
import type { EventMap, RawWebhook, WebhookEvent } from '../../core/types.js'
import { fromBase64, fromUtf8, toBase64Url, utf8 } from '../../crypto/encoding.js'
import { decodeJwt, verifyJwtSignature } from '../../crypto/jwt.js'

/** Where Google publishes the keys that sign its OIDC tokens. */
export const GOOGLE_PUBSUB_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs'

/** Both spellings appear in the wild; Google documents accepting either. */
const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com']

/**
 * Clock skew allowed on `exp` and `iat`, in seconds. The token carries its own
 * lifetime (about an hour), so this is not a replay window — just slack for
 * clocks that disagree.
 */
export const GOOGLE_PUBSUB_DEFAULT_SKEW = 300

/**
 * Google Pub/Sub push is signature family 5: nothing signs the body. The
 * request carries an OIDC JWT that authenticates *the caller* — Google's
 * push service acting as your service account — verified against Google's
 * rotating public keys, an audience, and the account's email. Trust in the
 * payload follows from trust in the caller plus TLS, which is why the
 * audience check matters: a token minted for someone else's endpoint must not
 * verify against yours.
 */
export interface GooglePubSubOptions {
  /**
   * The expected `aud` claim — by default Google sets it to the push endpoint
   * URL exactly as configured on the subscription, and it can be overridden
   * there. Required rather than defaulted from the request URL: behind a
   * proxy the request URL is whatever the proxy says, and an audience check
   * against an attacker-influenceable value checks nothing.
   */
  audience: string | string[]
  /**
   * Only accept tokens minted for these service accounts. Required: without
   * it, any Google-signed token with your audience would pass, and audiences
   * are not secrets — anyone can point their own push subscription at your
   * endpoint and have Google mint a valid token for it.
   */
  serviceAccountEmail: string | string[]
  /**
   * Where signing keys come from. Defaults to Google's JWKS endpoint with an
   * in-memory cache. Pass a `Jwk[]` to pin keys (tests, air-gapped setups)
   * or a `KeySet` to plug in your own cache.
   */
  keys?: Jwk[] | KeySet
  /** Fetch override for the default remote key set. */
  fetch?: typeof globalThis.fetch
  /** Clock skew allowed on `exp` and `iat`, in seconds. Defaults to 300. */
  tolerance?: number
  /**
   * Where the event name comes from. A string names a message attribute; a
   * function derives it from the decoded payload. Defaults to the constant
   * `message`, because Pub/Sub itself has no notion of an event type.
   */
  eventType?: string | ((payload: GooglePubSubEventPayload) => string | undefined)
}

/** The decoded message, unwrapped from the push envelope. */
export interface GooglePubSubMessage {
  messageId: string
  publishTime: string | undefined
  attributes: Record<string, string>
  orderingKey: string | undefined
  /** The base64 `data` field, decoded to bytes. */
  data: Uint8Array
  /** The data decoded as UTF-8. */
  text(): string
  /** The data parsed as JSON — what Gmail, Play RTDN, and Eventarc put there. */
  json<T = unknown>(): T
}

export interface GooglePubSubEventPayload {
  message: GooglePubSubMessage
  /** Full subscription resource name, `projects/…/subscriptions/…`. */
  subscription: string
  /** Present when the subscription has a dead-letter policy. */
  deliveryAttempt: number | undefined
}

export interface GooglePubSubEvents extends EventMap {
  message: GooglePubSubEventPayload
}

/** The wire shape of a push delivery. Google sends both field spellings. */
interface PushBody {
  message?: {
    data?: string
    attributes?: Record<string, string>
    messageId?: string
    message_id?: string
    publishTime?: string
    publish_time?: string
    orderingKey?: string
  }
  subscription?: string
  deliveryAttempt?: number
}

function toArray(value: string | string[] | undefined): string[] {
  if (!value) return []
  return (Array.isArray(value) ? value : [value]).filter(Boolean)
}

function toKeySet(options: GooglePubSubOptions): KeySet {
  if (Array.isArray(options.keys)) return staticKeySet(options.keys)
  if (options.keys) return options.keys
  return createRemoteKeySet({ url: GOOGLE_PUBSUB_JWKS_URL, fetch: options.fetch })
}

async function verifyWithKeys(
  raw: RawWebhook,
  options: GooglePubSubOptions,
  keySet: KeySet,
  ctx: VerifyContext,
): Promise<void> {
  const audiences = toArray(options.audience)
  if (audiences.length === 0) {
    throw new ConfigurationError('No expected audience was provided for Google Pub/Sub', {
      provider: 'google-pubsub',
    })
  }

  const emails = toArray(options.serviceAccountEmail)
  if (emails.length === 0) {
    throw new ConfigurationError(
      'No expected service account email was provided for Google Pub/Sub — without one, any Google-signed token bearing this audience would verify',
      { provider: 'google-pubsub' },
    )
  }

  const header = raw.header('authorization')
  if (!header) {
    throw new MissingSignatureError(
      'Missing Authorization header — enable authentication on the push subscription',
      { provider: 'google-pubsub' },
    )
  }

  const bearer = /^Bearer\s+(.+)$/i.exec(header)
  const jwt = bearer?.[1] ? decodeJwt(bearer[1]) : null
  if (!jwt) {
    throw new MissingSignatureError('Authorization header does not carry a well-formed JWT', {
      provider: 'google-pubsub',
    })
  }

  // Google signs these tokens with RS256 only. Pinning the algorithm before
  // touching key material forecloses algorithm-confusion attacks.
  if (jwt.header.alg !== 'RS256') {
    throw new SignatureVerificationError(
      `Expected an RS256 token, got "${jwt.header.alg ?? 'none'}"`,
      { provider: 'google-pubsub' },
    )
  }
  if (!jwt.header.kid) {
    throw new SignatureVerificationError('Token names no signing key (missing kid)', {
      provider: 'google-pubsub',
    })
  }

  const key = await keySet.get(jwt.header.kid, ctx.now)
  if (!key) {
    throw new SignatureVerificationError(`No Google signing key matches kid "${jwt.header.kid}"`, {
      provider: 'google-pubsub',
    })
  }

  if (!(await verifyJwtSignature(jwt, key))) {
    throw new SignatureVerificationError('Google Pub/Sub token signature does not verify', {
      provider: 'google-pubsub',
    })
  }

  const claims = jwt.payload
  if (typeof claims.iss !== 'string' || !GOOGLE_ISSUERS.includes(claims.iss)) {
    throw new SignatureVerificationError(`Token issuer is not Google: "${claims.iss}"`, {
      provider: 'google-pubsub',
    })
  }

  const tokenAudiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
  if (!tokenAudiences.some((aud) => typeof aud === 'string' && audiences.includes(aud))) {
    throw new SignatureVerificationError(
      'Token audience does not match this endpoint — a token minted for another audience must not verify here',
      { provider: 'google-pubsub' },
    )
  }

  const skew = ctx.tolerance ?? options.tolerance ?? GOOGLE_PUBSUB_DEFAULT_SKEW
  const nowSeconds = Math.floor(ctx.now.getTime() / 1000)
  if (typeof claims.exp !== 'number') {
    throw new SignatureVerificationError('Token carries no expiry', { provider: 'google-pubsub' })
  }
  if (nowSeconds > claims.exp + skew) {
    throw new TimestampToleranceError(
      `Token expired ${nowSeconds - claims.exp}s ago, beyond the ${skew}s clock skew`,
      { provider: 'google-pubsub' },
    )
  }
  if (typeof claims.iat === 'number' && claims.iat - skew > nowSeconds) {
    throw new TimestampToleranceError(`Token is issued ${claims.iat - nowSeconds}s in the future`, {
      provider: 'google-pubsub',
    })
  }

  if (
    typeof claims.email !== 'string' ||
    !emails.includes(claims.email) ||
    claims.email_verified !== true
  ) {
    throw new SignatureVerificationError(
      `Token is not for an expected service account: "${claims.email}"`,
      { provider: 'google-pubsub' },
    )
  }
}

/**
 * Verifies the OIDC token on a Pub/Sub push request.
 *
 * Standalone calls build a fresh key set each time, which means a JWKS fetch
 * per call unless `keys` is provided. The provider from `googlePubSub()`
 * builds the key set once and caches across deliveries — prefer it for
 * anything long-running.
 */
export async function verifyGooglePubSubWebhook(
  raw: RawWebhook,
  options: GooglePubSubOptions,
  ctx?: Partial<VerifyContext>,
): Promise<void> {
  await verifyWithKeys(raw, options, toKeySet(options), {
    now: ctx?.now ?? new Date(),
    tolerance: ctx?.tolerance ?? options.tolerance ?? GOOGLE_PUBSUB_DEFAULT_SKEW,
  })
}

function resolveType(
  payload: GooglePubSubEventPayload,
  eventType: GooglePubSubOptions['eventType'],
): string {
  if (typeof eventType === 'function') return eventType(payload) ?? 'message'
  if (typeof eventType === 'string') return payload.message.attributes[eventType] ?? 'message'
  return 'message'
}

/**
 * Turns a verified push request into a normalized event, unwrapping the
 * envelope: the interesting bytes arrive base64-encoded in `message.data`
 * inside a JSON body, and every service that publishes through Pub/Sub —
 * Gmail, Play RTDN, the Workspace Events API — nests its real payload there.
 */
export function parseGooglePubSubWebhook(
  raw: RawWebhook,
  options: Pick<GooglePubSubOptions, 'eventType'> = {},
): WebhookEvent<string, GooglePubSubEventPayload> {
  const body = raw.json<PushBody>()
  const messageId = body.message?.messageId ?? body.message?.message_id
  if (!body.message || typeof messageId !== 'string' || messageId === '') {
    throw new PayloadParseError('Pub/Sub push body has no message.messageId', {
      provider: 'google-pubsub',
    })
  }

  const data =
    typeof body.message.data === 'string' ? fromBase64(body.message.data) : new Uint8Array(0)
  const publishTime = body.message.publishTime ?? body.message.publish_time

  let text: string | undefined
  const message: GooglePubSubMessage = {
    messageId,
    publishTime,
    attributes: body.message.attributes ?? {},
    orderingKey: body.message.orderingKey,
    data,
    text() {
      if (text === undefined) text = fromUtf8(data)
      return text
    },
    json<T>() {
      try {
        return JSON.parse(this.text()) as T
      } catch (cause) {
        throw new PayloadParseError('Pub/Sub message data is not valid JSON', {
          provider: 'google-pubsub',
          cause,
        })
      }
    },
  }

  const payload: GooglePubSubEventPayload = {
    message,
    subscription: body.subscription ?? '',
    deliveryAttempt: body.deliveryAttempt,
  }

  const publishedAt = publishTime ? new Date(publishTime) : new Date()

  return {
    // Redelivery of an unacked message keeps its messageId, which is exactly
    // what the idempotency key wants.
    id: messageId,
    provider: 'google-pubsub',
    type: resolveType(payload, options.eventType),
    timestamp: Number.isNaN(publishedAt.getTime()) ? new Date() : publishedAt,
    payload,
    raw,
  }
}

/**
 * The Google Pub/Sub push integration — and, transitively, every Google
 * surface that delivers through Pub/Sub: Gmail watch, Play RTDN, Workspace
 * Events.
 *
 * There is no handshake, but the endpoint must answer inside Pub/Sub's ack
 * deadline or the message redelivers; do slow work after responding.
 *
 * ```ts
 * createWebhookHandler({
 *   provider: googlePubSub({
 *     audience: 'https://example.com/webhooks/pubsub',
 *     serviceAccountEmail: 'push@my-project.iam.gserviceaccount.com',
 *   }),
 *   on: { message: async (event) => { await handle(event.payload.message.json()) } },
 * })
 * ```
 */
export function googlePubSub(options: GooglePubSubOptions): WebhookProvider<GooglePubSubEvents> {
  // One key set for the provider's lifetime, so the JWKS cache actually caches.
  const keySet = toKeySet(options)

  return {
    id: 'google-pubsub',
    name: 'Google Pub/Sub',
    tolerance: options.tolerance ?? GOOGLE_PUBSUB_DEFAULT_SKEW,

    async verify(raw, ctx) {
      await verifyWithKeys(raw, options, keySet, ctx)
    },

    async parse(raw) {
      return parseGooglePubSubWebhook(raw, options)
    },
  }
}

export interface SignGooglePubSubOptions {
  audience: string
  /** Must match the `kid` on the JWK the verifier holds. */
  kid?: string
  email?: string
  emailVerified?: boolean
  issuer?: string
  issuedAt?: number
  expiresAt?: number
}

/**
 * Mints a token the way Google's push service would, as an `authorization`
 * header. For tests and local replay — pair it with `keys: [publicJwk]` on
 * the provider. Takes a private `CryptoKey` because the scheme is asymmetric.
 */
export async function signGooglePubSubWebhook(
  privateKey: CryptoKey,
  options: SignGooglePubSubOptions,
): Promise<Record<string, string>> {
  const issuedAt = options.issuedAt ?? Math.floor(Date.now() / 1000)
  const header = { alg: 'RS256', typ: 'JWT', kid: options.kid ?? 'test-key' }
  const claims = {
    iss: options.issuer ?? 'https://accounts.google.com',
    aud: options.audience,
    iat: issuedAt,
    exp: options.expiresAt ?? issuedAt + 3600,
    ...(options.email
      ? { email: options.email, email_verified: options.emailVerified ?? true }
      : {}),
  }

  const signedContent = `${toBase64Url(utf8(JSON.stringify(header)))}.${toBase64Url(
    utf8(JSON.stringify(claims)),
  )}`
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    utf8(signedContent) as BufferSource,
  )

  return { authorization: `Bearer ${signedContent}.${toBase64Url(new Uint8Array(signature))}` }
}
