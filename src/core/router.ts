import { UnknownProviderError } from './errors.js'
import type { WebhookHandler, WebhookHandlerOptions, WebhookResult } from './handler.js'
import { createWebhookHandler } from './handler.js'
import type { IdempotencyStore } from './idempotency.js'
import type { WebhookProvider } from './provider.js'
import type { EventHandler, EventMap, WebhookInput } from './types.js'

type SharedOptions = Pick<
  WebhookHandlerOptions<EventMap>,
  'onEvent' | 'onUnhandled' | 'onError' | 'tolerance' | 'now'
> & { idempotency?: IdempotencyStore }

export interface WebhookRouterOptions extends SharedOptions {
  /** Providers keyed by the slug that appears in the route. */
  // biome-ignore lint/suspicious/noExplicitAny: heterogeneous providers by design
  providers: Record<string, WebhookProvider<any>>
  /**
   * Picks which provider handles a request. Defaults to the last non-empty
   * path segment, which fits `/api/webhooks/[provider]`.
   */
  resolve?: (request: Request) => string | undefined
}

function lastPathSegment(request: Request): string | undefined {
  try {
    const segments = new URL(request.url).pathname.split('/').filter(Boolean)
    return segments.at(-1)
  } catch {
    return undefined
  }
}

/**
 * Fans one endpoint out to many providers.
 *
 * Worth using when several sources post to a single catch-all route. For one
 * provider per route, `createWebhookHandler` is the simpler thing.
 */
export class WebhookRouter {
  readonly #handlers = new Map<string, WebhookHandler>()
  readonly #resolve: (request: Request) => string | undefined

  constructor(options: WebhookRouterOptions) {
    this.#resolve = options.resolve ?? lastPathSegment
    for (const [slug, provider] of Object.entries(options.providers)) {
      this.#handlers.set(
        slug,
        createWebhookHandler({
          provider,
          onEvent: options.onEvent,
          onUnhandled: options.onUnhandled,
          onError: options.onError,
          tolerance: options.tolerance,
          idempotency: options.idempotency,
          now: options.now,
        }) as WebhookHandler,
      )
    }
  }

  /** Registers a handler for one provider's event type. Chainable. */
  on(provider: string, type: string, handler: EventHandler): this {
    const target = this.#handlers.get(provider)
    if (!target) {
      throw new UnknownProviderError(`No provider registered under "${provider}"`)
    }
    target.on(type, handler)
    return this
  }

  /** The handler for one provider, if registered. */
  handler(provider: string): WebhookHandler | undefined {
    return this.#handlers.get(provider)
  }

  /** Dispatches with an explicit provider slug. Never throws. */
  async process(provider: string, input: WebhookInput): Promise<WebhookResult> {
    const target = this.#handlers.get(provider)
    if (!target) {
      return {
        ok: false,
        outcome: 'failed',
        error: new UnknownProviderError(`No provider registered under "${provider}"`),
      }
    }
    return target.process(input)
  }

  /** Web-standard entry point: `export const POST = router.fetch`. */
  fetch = async (request: Request): Promise<Response> => {
    const slug = this.#resolve(request)
    const target = slug ? this.#handlers.get(slug) : undefined
    if (!target) {
      const error = new UnknownProviderError(
        slug
          ? `No provider registered under "${slug}"`
          : 'Could not determine the provider for this request',
      )
      return Response.json(error.toJSON(), { status: error.status })
    }
    return target.fetch(request)
  }
}
