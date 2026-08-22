import { memoryIdempotencyStore } from '../core/idempotency.js'
import type { WebhookEvent } from '../core/types.js'

export { memoryIdempotencyStore }

export interface TestRequestOptions {
  /** Ignored for GET and HEAD, which cannot carry a body. */
  body?: string | object
  headers?: Record<string, string>
  url?: string
  method?: string
}

/**
 * Builds a `Request` whose body bytes are exactly what you passed.
 *
 * If `body` is an object it is serialized once, and that same string is what
 * gets signed and sent — which is the property a signature test needs.
 */
export function createWebhookRequest(options: TestRequestOptions): Request {
  const method = options.method ?? 'POST'
  // GET and HEAD cannot carry a body. Several providers confirm an endpoint
  // with exactly such a request — Meta's `hub.challenge`, Dropbox's and
  // Okta's challenges — so building one has to be possible.
  const bodiless = method === 'GET' || method === 'HEAD'
  const body = typeof options.body === 'string' ? options.body : JSON.stringify(options.body)

  return new Request(options.url ?? 'https://example.test/api/webhooks', {
    method,
    headers: { 'content-type': 'application/json', ...options.headers },
    ...(bodiless ? {} : { body }),
  })
}

export interface EventRecorder {
  /** Pass as an `onEvent` handler. */
  readonly record: (event: WebhookEvent) => void
  readonly events: WebhookEvent[]
  readonly types: string[]
  clear(): void
}

/** Collects the events a handler dispatched, for assertions. */
export function eventRecorder(): EventRecorder {
  const events: WebhookEvent[] = []
  return {
    record: (event) => {
      events.push(event)
    },
    events,
    get types() {
      return events.map((event) => event.type)
    },
    clear() {
      events.length = 0
    },
  }
}
