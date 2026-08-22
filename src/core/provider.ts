import type { EventMap, EventName, RawWebhook, WebhookEvent } from './types.js'

export interface VerifyContext {
  /** Current time, injectable so tests do not depend on the wall clock. */
  readonly now: Date
  /** Replay window in seconds. */
  readonly tolerance: number
}

/**
 * The contract every integration implements.
 *
 * `verify` and `parse` are separate because they fail differently and callers
 * sometimes want only one: verification is a security boundary that throws,
 * parsing is a data transformation. The handler always runs `verify` first.
 */
export interface WebhookProvider<TEvents extends EventMap = EventMap> {
  /** Stable slug used in routes, logs, and idempotency keys. */
  readonly id: string
  /** Human-readable name for error messages. */
  readonly name: string
  /** Default replay window in seconds, if the scheme signs a timestamp. */
  readonly tolerance?: number

  /** Throws a `WebhookError` if the request is not authentic. */
  verify(raw: RawWebhook, ctx: VerifyContext): Promise<void>

  /** Turns a verified request into a normalized event. */
  parse(raw: RawWebhook): Promise<WebhookEvent<EventName<TEvents>, unknown>>

  /**
   * Answers a subscription handshake or liveness challenge instead of
   * dispatching — Slack's `url_verification`, Discord's PING, Meta's
   * `hub.challenge` GET, SNS `SubscriptionConfirmation`, Zoom's
   * `endpoint.url_validation`. Return `undefined` for ordinary deliveries.
   */
  handshake?(raw: RawWebhook, ctx: VerifyContext): Promise<Response | undefined>

  /**
   * Whether this provider's handshake carries a signature, which decides
   * whether `verify` runs before or after `handshake`.
   *
   * There is no single correct order. Meta's `hub.challenge`, Asana's
   * `X-Hook-Secret`, and Okta's and Dropbox's GET challenges are unsigned —
   * sometimes because that request is what establishes the secret — so they
   * must be answered first. Discord, Slack, and Zoom sign theirs, and Discord
   * actively probes a new endpoint with a deliberately invalid signature and
   * rejects the URL unless it receives a 401, so answering before verifying
   * would fail its own validation.
   *
   * Defaults to `false`, the safe assumption for a challenge that arrives
   * before any shared secret exists.
   */
  readonly signedHandshake?: boolean
}

/** Narrows a provider's event map for handler typing. */
export type EventsOf<TProvider> =
  TProvider extends WebhookProvider<infer TEvents> ? TEvents : EventMap
