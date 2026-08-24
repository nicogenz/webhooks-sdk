import { ConfigurationError } from '../core/errors.js'
import type { WebhookHandler } from '../core/handler.js'
import { toResponse } from '../core/handler.js'
import type { EventMap } from '../core/types.js'
import type { NodeRequestLike } from './node.js'
import { fromNodeRequest } from './node.js'

/**
 * Structural stand-in for an h3 `H3Event`, covering both major lines.
 * Declared here rather than imported so the package keeps zero dependencies.
 */
export interface H3EventLike {
  /**
   * h3 v2 puts the web-standard `Request` here. On v1 the same property is a
   * deprecated alias for the Node request, so the type must stay loose.
   */
  req?: unknown
  /** h3 v1: the underlying Node request. */
  node?: { req: NodeRequestLike }
}

/**
 * An event handler for h3 — the server engine under Nuxt and Nitro.
 *
 * ```ts
 * // server/api/webhooks/stripe.ts
 * export default defineEventHandler(toH3Handler(handler))
 * ```
 *
 * Both h3 lines are supported: v2 (Nitro v3) exposes the web `Request` as
 * `event.req`, while v1 (current Nuxt releases) wraps a Node request whose
 * untouched bytes are read off the stream. Either way the return value is a
 * web `Response`, which h3 has accepted from a handler since 1.8.
 *
 * Name the route file without a method suffix (`stripe.ts`, not
 * `stripe.post.ts`) when the provider confirms a new endpoint with a GET
 * challenge before delivering to it.
 */
export function toH3Handler<TEvents extends EventMap>(handler: WebhookHandler<TEvents>) {
  return async (event: H3EventLike): Promise<Response> => {
    if (event.req instanceof Request) return handler.fetch(event.req)

    const nodeRequest = event.node?.req
    if (!nodeRequest) {
      throw new ConfigurationError(
        'Expected an h3 event carrying a web Request (h3 v2) or a Node request (h3 v1)',
      )
    }
    return toResponse(await handler.process(await fromNodeRequest(nodeRequest)))
  }
}

/** `toH3Handler` under the name Nuxt users will look for. */
export const toNuxtHandler = toH3Handler

/** `toH3Handler` under the name Nitro users will look for. */
export const toNitroHandler = toH3Handler
