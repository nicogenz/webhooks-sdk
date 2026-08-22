import type { WebhookHandler } from '../core/handler.js'
import type { EventMap } from '../core/types.js'
import type { NodeRequestLike, NodeResponseLike } from './node.js'
import { toNodeHandler } from './node.js'

export interface ExpressRequestLike extends NodeRequestLike {
  /** Set by `captureRawBody`. A Node Buffer satisfies this. */
  rawBody?: Uint8Array
  /** `express.raw()` leaves the untouched bytes here, as a Buffer. */
  body?: unknown
}

/**
 * A `verify` callback for `express.json()` / `body-parser` that stashes the
 * untouched bytes on the request before they are parsed away.
 *
 * ```ts
 * app.use(express.json({ verify: captureRawBody }))
 * ```
 *
 * The better option when a route is webhooks-only is to mount `express.raw()`
 * with a catch-all content type on that path, so the body is never parsed.
 */
export function captureRawBody(
  request: ExpressRequestLike,
  _response: unknown,
  buffer: Uint8Array,
): void {
  request.rawBody = buffer
}

/**
 * Express middleware for a webhook handler.
 *
 * Mount `express.raw()` on the route, mount this before any JSON body parser,
 * or make sure `captureRawBody` ran.
 */
export function toExpressHandler<TEvents extends EventMap>(handler: WebhookHandler<TEvents>) {
  const nodeHandler = toNodeHandler(handler)

  return async (request: ExpressRequestLike, response: NodeResponseLike): Promise<void> => {
    // `captureRawBody` stashes the bytes on `rawBody`; `express.raw()` leaves
    // them on `body` as a Buffer — and has already drained the stream, so
    // they must be picked up here or verification would see an empty body.
    const bytes = request.rawBody ?? (request.body instanceof Uint8Array ? request.body : undefined)
    const captured = bytes
      ? new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)
      : undefined
    await nodeHandler(request, response, captured)
  }
}
