import { ConfigurationError, MissingSignatureError } from '../../core/errors.js'
import type { VerifyContext, WebhookProvider } from '../../core/provider.js'
import type { HmacProviderConfig, SignatureMaterial } from '../../core/scheme.js'
import { createHmacProvider, verifyWithScheme } from '../../core/scheme.js'
import type { EventMap, RawWebhook, WebhookEvent } from '../../core/types.js'
import { digestHex } from '../../crypto/hash.js'
import { hmacBase64 } from '../../crypto/hmac.js'

export const TWILIO_SIGNATURE_HEADER = 'x-twilio-signature'

/**
 * Twilio is signature family 7: the HMAC covers a string this SDK has to
 * rebuild — the full public URL of the endpoint plus the sorted form
 * parameters — rather than the raw body. That makes the URL part of the
 * security boundary, and it is the one input the request itself cannot be
 * trusted to know: a proxy that terminates TLS or rewrites the host changes
 * what your server sees without changing what Twilio signed.
 */
export interface TwilioOptions {
  /**
   * The account's auth token. Pass `[primary, secondary]` while a secondary
   * token is promoted during a rotation.
   */
  authToken: string | string[]
  /**
   * The exact URL configured in the Twilio console, including scheme, host,
   * and any query string. Defaults to the request URL, which is correct only
   * when no proxy rewrites it — behind a load balancer or tunnel, set this
   * explicitly. A function receives the request and returns the URL, for
   * multi-tenant endpoints.
   *
   * When a plain string without a query is given, the request's own query
   * string is carried over — Twilio appends parameters (`bodySHA256`, GET
   * webhooks) to the URL it was configured with, and those are signed.
   */
  url?: string | ((raw: RawWebhook) => string)
}

/**
 * Status-callback and inbound event names this SDK derives, for autocomplete.
 * Twilio has no single event-name field; see `parseTwilioWebhook` for how
 * these are constructed. Any other string still routes.
 */
export interface TwilioEvents extends EventMap {
  'message.received': Record<string, string>
  'message.queued': Record<string, string>
  'message.sending': Record<string, string>
  'message.sent': Record<string, string>
  'message.delivered': Record<string, string>
  'message.undelivered': Record<string, string>
  'message.failed': Record<string, string>
  'message.read': Record<string, string>
  'call.initiated': Record<string, string>
  'call.ringing': Record<string, string>
  'call.in-progress': Record<string, string>
  'call.answered': Record<string, string>
  'call.completed': Record<string, string>
  'call.busy': Record<string, string>
  'call.no-answer': Record<string, string>
  'call.canceled': Record<string, string>
  'call.failed': Record<string, string>
}

const BODY_HASH_PARAM = /([?&]bodySHA256=)[^&]*/

function isFormEncoded(raw: RawWebhook): boolean {
  return (raw.header('content-type') ?? '').toLowerCase().includes('x-www-form-urlencoded')
}

/**
 * Parses the form body into the flat record Twilio signed. Repeated keys are
 * comma-joined, matching how Twilio's reference implementation coerces the
 * arrays a body parser produces.
 */
function formParams(raw: RawWebhook): Record<string, string> {
  const params: Record<string, string> = {}
  if (!isFormEncoded(raw) || raw.body.length === 0) return params
  for (const [key, value] of new URLSearchParams(raw.text())) {
    const existing = params[key]
    params[key] = existing === undefined ? value : `${existing},${value}`
  }
  return params
}

function resolveUrl(options: TwilioOptions, raw: RawWebhook): string {
  const configured = typeof options.url === 'function' ? options.url(raw) : options.url
  let url = configured ?? raw.url

  if (!url) {
    throw new ConfigurationError(
      'Twilio signs the endpoint URL, and neither the request nor the options carry one — set `url`',
      { provider: 'twilio' },
    )
  }

  // Twilio appends query parameters to the configured URL and signs the
  // result, so a static override without a query adopts the request's.
  if (typeof options.url === 'string' && !options.url.includes('?') && raw.url) {
    const query = raw.url.indexOf('?')
    if (query !== -1) url = options.url + raw.url.slice(query)
  }

  // Node's `req.url` is a path, not a URL. Failing every delivery with "bad
  // signature" over that would be undebuggable; fail loudly as config instead.
  if (!/^https?:\/\//i.test(url)) {
    throw new ConfigurationError(
      `Twilio needs the absolute public URL, got "${url}" — behind the Node adapter or a proxy, set \`url\` explicitly`,
      { provider: 'twilio' },
    )
  }

  return url
}

/** Rebuilds `url + k1v1k2v2…` — the exact string Twilio signs. */
function signedContent(url: string, params: Record<string, string>): string {
  return Object.keys(params)
    .sort()
    .reduce((acc, key) => acc + key + params[key], url)
}

async function contentFor(options: TwilioOptions, raw: RawWebhook): Promise<string> {
  const url = resolveUrl(options, raw)

  // JSON (and other non-form) webhooks: Twilio appends `bodySHA256=<hex>` to
  // the URL and signs only the URL. Substituting the hash of the body we
  // actually received means a tampered body changes the rebuilt string and the
  // HMAC comparison fails on its own — no separate hash equality check whose
  // timing or ordering could be gotten wrong.
  if (BODY_HASH_PARAM.test(url)) {
    const hash = await digestHex('SHA-256', raw.body)
    return url.replace(BODY_HASH_PARAM, `$1${hash}`)
  }

  return signedContent(url, formParams(raw))
}

function extract(raw: RawWebhook): SignatureMaterial {
  const header = raw.header(TWILIO_SIGNATURE_HEADER)
  if (!header) {
    throw new MissingSignatureError(`Missing ${TWILIO_SIGNATURE_HEADER} header`, {
      provider: 'twilio',
    })
  }
  return { candidates: [header] }
}

/**
 * Turns a verified Twilio request into a normalized event.
 *
 * Twilio has no event-name field, so the type is derived: `EventType` verbatim
 * where a product sends one (Conversations, TaskRouter, Sync), otherwise
 * `message.<status>` / `call.<status>` from the delivery-status fields, and
 * `unknown` past that. The id folds the derived type into the SID because a
 * SID alone is not a delivery id — every status callback for one message
 * carries the same `MessageSid`, and deduplicating on it would drop all but
 * the first.
 */
export function parseTwilioWebhook(raw: RawWebhook): WebhookEvent<string, unknown> {
  // No timestamp anywhere on the wire, so receipt time is the honest answer.
  const receivedAt = new Date()

  if (!isFormEncoded(raw)) {
    const payload = raw.json<Record<string, unknown>>()
    const eventType = payload.EventType ?? payload.event_type
    const sid = payload.Sid ?? payload.sid
    const type = typeof eventType === 'string' ? eventType : 'unknown'
    return {
      id: typeof sid === 'string' ? `${sid}:${type}` : '',
      provider: 'twilio',
      type,
      timestamp: receivedAt,
      payload,
      raw,
    }
  }

  const params = formParams(raw)
  const messageStatus = params.MessageStatus ?? params.SmsStatus
  const type =
    params.EventType ??
    (messageStatus
      ? `message.${messageStatus}`
      : params.CallStatus
        ? `call.${params.CallStatus}`
        : 'unknown')
  const sid = params.MessageSid ?? params.CallSid ?? params.SmsSid

  return {
    id: sid ? `${sid}:${type}` : '',
    provider: 'twilio',
    type,
    timestamp: receivedAt,
    payload: params,
    raw,
  }
}

/**
 * Twilio signs `url + sortedParams` with HMAC-SHA1 and base64-encodes it.
 * Nothing in the signed material varies with time, so the scheme has no replay
 * protection of its own — pair it with an idempotency store.
 */
function schemeFor(options: TwilioOptions): HmacProviderConfig {
  return {
    id: 'twilio',
    name: 'Twilio',
    secret: options.authToken,
    encoding: 'base64',
    algorithm: 'SHA-1',
    extract,
    content: (_material, raw) => contentFor(options, raw),
    event: parseTwilioWebhook,
  }
}

/** Verifies a Twilio webhook signature. */
export async function verifyTwilioWebhook(
  raw: RawWebhook,
  options: TwilioOptions,
  ctx?: Partial<VerifyContext>,
): Promise<void> {
  await verifyWithScheme(raw, schemeFor(options), ctx)
}

/**
 * The Twilio integration. Covers the form-encoded webhooks every product
 * sends by default and the JSON variant that signs a `bodySHA256` URL
 * parameter instead of the parameters.
 *
 * ```ts
 * createWebhookHandler({
 *   provider: twilio({
 *     authToken: process.env.TWILIO_AUTH_TOKEN!,
 *     url: 'https://example.com/webhooks/twilio',
 *   }),
 *   idempotency: memoryIdempotencyStore(), // the scheme signs no timestamp
 *   on: { 'message.received': async (event) => { … } },
 * })
 * ```
 */
export function twilio(options: TwilioOptions): WebhookProvider<TwilioEvents> {
  return createHmacProvider<TwilioEvents>(schemeFor(options))
}

/**
 * Produces a valid `X-Twilio-Signature` value for a URL and its form
 * parameters. For tests and local replay. For the JSON flow, append
 * `bodySHA256=<hex sha256 of the body>` to the URL and pass no params.
 */
export async function signTwilioWebhook(
  url: string,
  params: Record<string, string>,
  authToken: string,
): Promise<string> {
  return hmacBase64('SHA-1', authToken, signedContent(url, params))
}
