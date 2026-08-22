import type { WebhookHandler } from '../core/handler.js'
import type { EventMap } from '../core/types.js'

/**
 * Route handlers for the Next.js App Router.
 *
 * ```ts
 * // app/api/webhooks/stripe/route.ts
 * export const { POST } = toNextRoute(handler)
 * ```
 *
 * App Router route handlers already receive a Web `Request` with an unread
 * body, so nothing has to be reconstructed. A `GET` is exported too, for the
 * providers that confirm an endpoint with a challenge query parameter before
 * they will send anything to it.
 *
 * The Pages Router is different: it parses the body before your code runs, so
 * you must set `export const config = { api: { bodyParser: false } }` and use
 * the `webhooks-sdk/node` adapter instead.
 */
export function toNextRoute<TEvents extends EventMap>(handler: WebhookHandler<TEvents>) {
  const route = (request: Request): Promise<Response> => handler.fetch(request)
  return { POST: route, GET: route, PUT: route }
}
