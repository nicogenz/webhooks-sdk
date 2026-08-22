/**
 * A verified, normalized webhook delivery.
 *
 * Everything above `payload` is the same shape for every provider. `payload`
 * stays provider-native on purpose — a Stripe PaymentIntent and a GitHub push
 * have nothing in common, and pretending otherwise would lose information.
 * A cross-provider `semantic` view is reserved for a later release.
 */
export interface WebhookEvent<TType extends string = string, TPayload = unknown> {
  /** Provider-assigned delivery or event id, used for idempotency. */
  readonly id: string
  /** Provider slug, e.g. `stripe`. */
  readonly provider: string
  /** Provider-native event name, e.g. `payment_intent.succeeded`. */
  readonly type: TType
  /** When the provider says the event happened. Falls back to receipt time. */
  readonly timestamp: Date
  /** The provider's own event body. */
  readonly payload: TPayload
  /** The raw request, kept so handlers can re-verify or log verbatim. */
  readonly raw: RawWebhook
}

/**
 * The inbound request, normalized across runtimes and frozen before
 * verification. `body` is the exact bytes received — any re-serialization
 * would invalidate the signature.
 */
export interface RawWebhook {
  readonly headers: Headers
  readonly body: Uint8Array
  readonly method: string
  readonly url: string | undefined
  /** Case-insensitive header lookup. */
  header(name: string): string | null
  /** The body decoded as UTF-8. */
  text(): string
  /** The body parsed as JSON. Throws `PayloadParseError` if it is not JSON. */
  json<T = unknown>(): T
}

/** Anything the SDK can normalize into a `RawWebhook`. */
export type WebhookInput =
  | Request
  | RawWebhook
  | {
      headers: Headers | Record<string, string | string[] | undefined>
      body: string | Uint8Array | ArrayBuffer
      method?: string
      url?: string
    }

/** Maps provider event names to their payload types. */
export type EventMap = Record<string, unknown>

/**
 * Known event names for a provider, while still accepting any string.
 * The `string & {}` arm keeps autocomplete for known names without rejecting
 * events a provider added after this release.
 */
export type EventName<TEvents extends EventMap> = (keyof TEvents & string) | (string & {})

export type PayloadOf<TEvents extends EventMap, TType> = TType extends keyof TEvents
  ? TEvents[TType]
  : unknown

export type EventHandler<TEvent extends WebhookEvent = WebhookEvent> = (
  event: TEvent,
) => void | Promise<void>

export type EventHandlers<TEvents extends EventMap> = {
  [K in EventName<TEvents>]?: EventHandler<WebhookEvent<K & string, PayloadOf<TEvents, K>>>
}

/** What happened to a delivery. */
export type WebhookOutcome =
  /** Verified, and at least one handler ran. */
  | 'handled'
  /** Verified, but nothing was registered for this event type. */
  | 'unhandled'
  /** Already processed — suppressed by the idempotency store. */
  | 'duplicate'
  /** A provider handshake or challenge, answered without dispatching. */
  | 'handshake'
  /** Rejected before dispatch, or a handler threw. */
  | 'failed'
