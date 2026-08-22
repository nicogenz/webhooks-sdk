import { fromUtf8, toBytes } from '../crypto/encoding.js'
import { PayloadParseError } from './errors.js'
import type { RawWebhook, WebhookInput } from './types.js'

function isRawWebhook(input: WebhookInput): input is RawWebhook {
  return typeof (input as RawWebhook).header === 'function'
}

function toHeaders(input: Headers | Record<string, string | string[] | undefined>): Headers {
  if (input instanceof Headers) return input
  const headers = new Headers()
  for (const [key, value] of Object.entries(input)) {
    if (value === undefined) continue
    // Node collapses repeated headers into an array; join the way HTTP does.
    headers.set(key, Array.isArray(value) ? value.join(', ') : value)
  }
  return headers
}

function createRawWebhook(init: {
  headers: Headers
  body: Uint8Array
  method: string
  url: string | undefined
}): RawWebhook {
  let text: string | undefined
  return {
    headers: init.headers,
    body: init.body,
    method: init.method,
    url: init.url,
    header(name) {
      return init.headers.get(name)
    },
    text() {
      if (text === undefined) text = fromUtf8(init.body)
      return text
    },
    json<T>() {
      try {
        return JSON.parse(this.text()) as T
      } catch (cause) {
        throw new PayloadParseError('Webhook body is not valid JSON', { cause })
      }
    },
  }
}

/**
 * Normalizes any supported input into a `RawWebhook`.
 *
 * The body is read once, as bytes, and never re-encoded. This is the whole
 * reason the SDK takes raw input rather than a parsed object: every signature
 * scheme signs the exact bytes on the wire, so `JSON.parse` followed by
 * `JSON.stringify` silently breaks verification through key reordering,
 * whitespace, or unicode escaping.
 */
export async function toRawWebhook(input: WebhookInput): Promise<RawWebhook> {
  if (isRawWebhook(input)) return input

  if (input instanceof Request) {
    return createRawWebhook({
      headers: input.headers,
      body: new Uint8Array(await input.clone().arrayBuffer()),
      method: input.method,
      url: input.url,
    })
  }

  return createRawWebhook({
    headers: toHeaders(input.headers),
    body: toBytes(input.body),
    method: input.method ?? 'POST',
    url: input.url,
  })
}
