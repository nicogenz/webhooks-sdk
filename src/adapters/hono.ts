import type { WebhookHandler } from '../core/handler.js'
import type { EventMap } from '../core/types.js'

interface HonoContextLike {
  req: { raw: Request }
}

/**
 * A Hono handler.
 *
 * ```ts
 * app.post('/webhooks/stripe', toHonoHandler(handler))
 * ```
 *
 * Works unchanged on Cloudflare Workers, Deno, and Bun — the SDK only uses
 * `fetch` and Web Crypto.
 */
export function toHonoHandler<TEvents extends EventMap>(handler: WebhookHandler<TEvents>) {
  return (c: HonoContextLike): Promise<Response> => handler.fetch(c.req.raw)
}
