import type { WebhookHandler } from '../core/handler.js'
import type { EventMap, WebhookInput } from '../core/types.js'

/**
 * Structural stand-ins for `http.IncomingMessage` / `http.ServerResponse`.
 * Declared here rather than imported so the package keeps zero dependencies
 * and its published types do not require `@types/node`.
 */
export interface NodeRequestLike {
  method?: string | undefined
  url?: string | undefined
  headers: Record<string, string | string[] | undefined>
  [Symbol.asyncIterator](): AsyncIterableIterator<Uint8Array | string>
}

export interface NodeResponseLike {
  statusCode: number
  setHeader(name: string, value: string): unknown
  end(chunk?: string): unknown
}

/**
 * Reads the untouched request bytes off a Node stream.
 *
 * Every body-parsing middleware in the Node ecosystem consumes this stream and
 * hands back a parsed object. Once that happens the original bytes are gone
 * and no signature can be checked, which is the single most common reason
 * webhook verification "randomly" fails in Express apps.
 */
export async function readRawBody(request: NodeRequestLike): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []
  let length = 0
  const encoder = new TextEncoder()

  for await (const chunk of request) {
    const bytes = typeof chunk === 'string' ? encoder.encode(chunk) : chunk
    chunks.push(bytes)
    length += bytes.length
  }

  const body = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.length
  }
  return body
}

/** Normalizes a Node request into something the handler accepts. */
export async function fromNodeRequest(
  request: NodeRequestLike,
  rawBody?: Uint8Array,
): Promise<WebhookInput> {
  return {
    headers: request.headers,
    body: rawBody ?? (await readRawBody(request)),
    method: request.method ?? 'POST',
    url: request.url,
  }
}

/**
 * Wraps a handler as a `(req, res)` listener for `node:http`.
 *
 * Pass `rawBody` if a middleware already captured the untouched bytes.
 */
export function toNodeHandler<TEvents extends EventMap>(handler: WebhookHandler<TEvents>) {
  return async (
    request: NodeRequestLike,
    response: NodeResponseLike,
    rawBody?: Uint8Array,
  ): Promise<void> => {
    const result = await handler.process(await fromNodeRequest(request, rawBody))

    if (result.response) {
      response.statusCode = result.response.status
      response.setHeader(
        'content-type',
        result.response.headers.get('content-type') ?? 'text/plain',
      )
      response.end(await result.response.text())
      return
    }

    response.statusCode = result.error?.status ?? 200
    response.setHeader('content-type', 'application/json')
    response.end(
      JSON.stringify(result.error ? result.error.toJSON() : { ok: true, outcome: result.outcome }),
    )
  }
}
