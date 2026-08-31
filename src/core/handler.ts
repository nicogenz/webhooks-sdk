import { DuplicateEventError, HandlerError, isWebhookError, WebhookError } from './errors.js'
import type { IdempotencyStore } from './idempotency.js'
import type { VerifyContext, WebhookProvider } from './provider.js'
import { toRawWebhook } from './request.js'
import type {
  EventHandler,
  EventHandlers,
  EventMap,
  EventName,
  WebhookEvent,
  WebhookInput,
  WebhookOutcome,
} from './types.js'

/** The default replay window. Five minutes is what most providers assume. */
export const DEFAULT_TOLERANCE_SECONDS = 300

export interface WebhookResult {
  ok: boolean
  outcome: WebhookOutcome
  /** Present whenever verification succeeded. */
  event?: WebhookEvent
  /** Present when `outcome` is `failed`. */
  error?: WebhookError
  /** Present when `outcome` is `handshake`. */
  response?: Response
}

export interface WebhookHandlerOptions<TEvents extends EventMap> {
  provider: WebhookProvider<TEvents>
  /** Handlers keyed by provider-native event name. */
  on?: EventHandlers<TEvents>
  /** Runs for every verified event, before the type-specific handlers. */
  onEvent?: EventHandler
  /** Runs when no handler matched. Useful for discovering event names. */
  onUnhandled?: EventHandler
  /** Runs for every failure. Never throws into the response path. */
  onError?: (error: WebhookError, raw?: WebhookInput) => void | Promise<void>
  /** Replay window override, in seconds. */
  tolerance?: number
  /** Suppresses events whose id has already been processed. */
  idempotency?: IdempotencyStore
  /** Clock injection point for tests. */
  now?: () => Date
}

export interface WebhookHandler<TEvents extends EventMap = EventMap> {
  readonly provider: WebhookProvider<TEvents>
  /** Registers a handler after construction. Chainable. */
  on<K extends EventName<TEvents>>(
    type: K,
    handler: NonNullable<EventHandlers<TEvents>[K]>,
  ): WebhookHandler<TEvents>
  /** Verify, parse, and dispatch. Never throws — inspect the result. */
  process(input: WebhookInput): Promise<WebhookResult>
  /** Web-standard entry point: `export const POST = handler.fetch`. */
  fetch(request: Request): Promise<Response>
}

/**
 * Converts a `process()` result into the `Response` that `handler.fetch`
 * would produce. Exported for adapters that read the request themselves but
 * still respond with a Web-standard `Response`.
 */
export function toResponse(result: WebhookResult): Response {
  if (result.response) return result.response

  if (result.error) {
    return Response.json(result.error.toJSON(), { status: result.error.status })
  }

  // Unhandled events still get a 2xx. A 404 here would make providers retry
  // and eventually disable the endpoint over event types we simply ignore.
  return Response.json({ ok: true, outcome: result.outcome }, { status: 200 })
}

export function createWebhookHandler<TEvents extends EventMap = EventMap>(
  options: WebhookHandlerOptions<TEvents>,
): WebhookHandler<TEvents> {
  const { provider, idempotency, now = () => new Date() } = options
  const handlers = new Map<string, EventHandler[]>()

  for (const [type, handler] of Object.entries(options.on ?? {})) {
    if (handler) handlers.set(type, [handler as EventHandler])
  }

  const tolerance = options.tolerance ?? provider.tolerance ?? DEFAULT_TOLERANCE_SECONDS

  const report = async (error: WebhookError, input?: WebhookInput): Promise<WebhookResult> => {
    try {
      await options.onError?.(error, input)
    } catch {
      // An onError that throws must not mask the original failure.
    }
    return { ok: false, outcome: 'failed', error }
  }

  const handler: WebhookHandler<TEvents> = {
    provider,

    on(type, eventHandler) {
      const existing = handlers.get(type as string)
      if (existing) existing.push(eventHandler as EventHandler)
      else handlers.set(type as string, [eventHandler as EventHandler])
      return handler
    },

    async process(input) {
      const ctx: VerifyContext = { now: now(), tolerance }

      let raw: Awaited<ReturnType<typeof toRawWebhook>>
      try {
        raw = await toRawWebhook(input)
      } catch (cause) {
        return report(asWebhookError(cause, provider.id), input)
      }

      // Providers that sign their handshake are verified first; the rest are
      // answered before verification, because for them no secret exists yet.
      let verified = false
      if (provider.handshake) {
        try {
          if (provider.signedHandshake) {
            await provider.verify(raw, ctx)
            verified = true
          }
          const challenge = await provider.handshake(raw, ctx)
          if (challenge) return { ok: true, outcome: 'handshake', response: challenge }
        } catch (cause) {
          return report(asWebhookError(cause, provider.id), input)
        }
      }

      let event: WebhookEvent
      try {
        if (!verified) await provider.verify(raw, ctx)
        event = await provider.parse(raw)
      } catch (cause) {
        return report(asWebhookError(cause, provider.id), input)
      }

      // A blank id must never reach the store. The key would collapse to
      // `provider:` for every delivery, so the first event would suppress all
      // later ones as duplicates — and a duplicate is acknowledged with a 200,
      // so the provider would never retry. Silent loss is worse than no
      // deduplication, which is why this skips rather than throws. Providers
      // whose deliveries carry no natural id should synthesise one in `parse`.
      const idempotencyKey = idempotency && event.id !== '' ? `${provider.id}:${event.id}` : null
      if (idempotency && idempotencyKey) {
        try {
          if (await idempotency.seen(idempotencyKey)) {
            const error = new DuplicateEventError(`Event ${event.id} was already processed`, {
              provider: provider.id,
            })
            await options.onError?.(error, input)
            return { ok: true, outcome: 'duplicate', event, error }
          }
        } catch (cause) {
          return report(asWebhookError(cause, provider.id), input)
        }
      }

      const matched = handlers.get(event.type) ?? []

      try {
        await options.onEvent?.(event)
        for (const fn of matched) await fn(event)
        if (matched.length === 0) await options.onUnhandled?.(event)
      } catch (cause) {
        const error =
          isWebhookError(cause) && cause.code !== 'handler_failed'
            ? cause
            : new HandlerError(`Handler for "${event.type}" failed: ${messageOf(cause)}`, {
                provider: provider.id,
                cause,
              })
        const reported = await report(error, input)
        return { ...reported, event }
      }

      // Remembered only after dispatch succeeds. Remembering first would turn
      // the retry of a failed handler into a "duplicate" — acknowledged with
      // a 200 and never re-run — permanently dropping the event the 500 was
      // supposed to bring back.
      if (idempotency && idempotencyKey) {
        try {
          await idempotency.remember(idempotencyKey)
        } catch {
          // The event is already handled; failing the delivery now would make
          // the provider retry and re-run it. A lost dedup record costs at
          // most one re-run on redelivery, which at-least-once delivery
          // already implies.
        }
      }

      return { ok: true, outcome: matched.length > 0 ? 'handled' : 'unhandled', event }
    },

    async fetch(request) {
      return toResponse(await handler.process(request))
    },
  }

  return handler
}

function messageOf(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause)
}

export function asWebhookError(cause: unknown, provider?: string): WebhookError {
  if (isWebhookError(cause)) return cause
  return new WebhookError('invalid_payload', messageOf(cause), { provider, cause })
}
