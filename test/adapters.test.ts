import { describe, expect, it, vi } from 'vitest'
import { captureRawBody, toExpressHandler } from '../src/adapters/express.js'
import { toH3Handler, toNitroHandler, toNuxtHandler } from '../src/adapters/h3.js'
import { toHonoHandler } from '../src/adapters/hono.js'
import { toNextRoute } from '../src/adapters/next.js'
import type { NodeRequestLike, NodeResponseLike } from '../src/adapters/node.js'
import { fromNodeRequest, readRawBody, toNodeHandler } from '../src/adapters/node.js'
import { createWebhookHandler } from '../src/index.js'
import { signStripeWebhook, stripe } from '../src/providers/stripe/index.js'
import { createWebhookRequest } from '../src/testing/index.js'

const SECRET = 'whsec_adapters'
const NOW = new Date('2026-08-20T12:00:00Z')
const TS = Math.floor(NOW.getTime() / 1000)

const EVENT = {
  id: 'evt_adapter',
  object: 'event' as const,
  type: 'charge.succeeded',
  created: TS,
  data: { object: { id: 'ch_1' } },
}
const BODY = JSON.stringify(EVENT)

const handler = (on?: Record<string, () => void>) =>
  createWebhookHandler({ provider: stripe({ secret: SECRET }), now: () => NOW, on })

/** A stand-in for http.IncomingMessage that streams the given chunks. */
function nodeRequest(
  chunks: (string | Uint8Array)[],
  headers: Record<string, string | string[] | undefined>,
): NodeRequestLike {
  return {
    method: 'POST',
    url: '/webhooks/stripe',
    headers,
    async *[Symbol.asyncIterator]() {
      for (const chunk of chunks) yield chunk
    },
  }
}

function nodeResponse() {
  const sent = { statusCode: 0, headers: {} as Record<string, string>, body: '' }
  const res: NodeResponseLike = {
    get statusCode() {
      return sent.statusCode
    },
    set statusCode(value: number) {
      sent.statusCode = value
    },
    setHeader(name, value) {
      sent.headers[name] = value
    },
    end(chunk) {
      sent.body = chunk ?? ''
    },
  }
  return { res, sent }
}

describe('readRawBody', () => {
  it('reassembles chunks byte-for-byte across a split', async () => {
    // A body arriving in pieces must produce the same bytes as one piece, or
    // every signature over a chunked request fails.
    const split = [BODY.slice(0, 7), BODY.slice(7, 30), BODY.slice(30)]
    const body = await readRawBody(nodeRequest(split, {}))
    expect(new TextDecoder().decode(body)).toBe(BODY)
  })

  it('handles Uint8Array chunks and a mix of both', async () => {
    const encoder = new TextEncoder()
    const mixed = [encoder.encode(BODY.slice(0, 10)), BODY.slice(10)]
    expect(new TextDecoder().decode(await readRawBody(nodeRequest(mixed, {})))).toBe(BODY)
  })

  it('preserves multi-byte characters split across a chunk boundary', async () => {
    // Splitting mid-codepoint is where a naive string concat corrupts the body.
    const payload = JSON.stringify({ note: 'héllo — wörld 🎉' })
    const bytes = new TextEncoder().encode(payload)
    const chunks = [bytes.slice(0, 9), bytes.slice(9, 21), bytes.slice(21)]
    expect(new TextDecoder().decode(await readRawBody(nodeRequest(chunks, {})))).toBe(payload)
  })

  it('produces an empty body for no chunks', async () => {
    expect(await readRawBody(nodeRequest([], {}))).toEqual(new Uint8Array(0))
  })
})

describe('node adapter', () => {
  it('verifies a signature over a chunked stream end to end', async () => {
    const signature = await signStripeWebhook(BODY, SECRET, TS)
    const handled = vi.fn()
    const { res, sent } = nodeResponse()

    await toNodeHandler(handler({ 'charge.succeeded': handled }))(
      nodeRequest([BODY.slice(0, 12), BODY.slice(12)], { 'stripe-signature': signature }),
      res,
    )

    expect(sent.statusCode).toBe(200)
    expect(JSON.parse(sent.body)).toEqual({ ok: true, outcome: 'handled' })
    expect(handled).toHaveBeenCalledOnce()
  })

  it('maps a verification failure to its status code', async () => {
    const { res, sent } = nodeResponse()
    await toNodeHandler(handler())(
      nodeRequest([BODY], { 'stripe-signature': 't=1,v1=deadbeef' }),
      res,
    )
    expect(sent.statusCode).toBe(400)
    expect(JSON.parse(sent.body).error).toBe('timestamp_out_of_tolerance')
  })

  it('accepts a pre-read body instead of consuming the stream again', async () => {
    const signature = await signStripeWebhook(BODY, SECRET, TS)
    const { res, sent } = nodeResponse()
    // A stream that would throw if read — proving the captured bytes are used.
    const exhausted: NodeRequestLike = {
      method: 'POST',
      headers: { 'stripe-signature': signature },
      // Deliberately unreadable: reading it at all is the failure.
      [Symbol.asyncIterator]() {
        throw new Error('stream already consumed')
      },
    }

    await toNodeHandler(handler())(exhausted, res, new TextEncoder().encode(BODY))
    expect(sent.statusCode).toBe(200)
  })

  it('joins repeated headers the way HTTP does', async () => {
    const input = await fromNodeRequest(
      nodeRequest([BODY], { 'x-multi': ['a', 'b'], 'x-single': 'c', 'x-absent': undefined }),
    )
    const headers = (input as { headers: Record<string, string> }).headers
    expect(headers['x-multi']).toEqual(['a', 'b'])
    expect(headers['x-single']).toBe('c')
  })

  it('writes a handshake response through verbatim', async () => {
    const provider = {
      id: 'h',
      name: 'H',
      verify: async () => {},
      parse: async () => {
        throw new Error('unreachable')
      },
      handshake: async () => new Response('challenge-echo', { status: 200 }),
    }
    const { res, sent } = nodeResponse()
    await toNodeHandler(createWebhookHandler({ provider }))(nodeRequest(['{}'], {}), res)
    expect(sent.body).toBe('challenge-echo')
    expect(sent.statusCode).toBe(200)
  })
})

describe('express adapter', () => {
  it('uses a Buffer captured by a body parser, honouring its byteOffset', async () => {
    const signature = await signStripeWebhook(BODY, SECRET, TS)
    // Node pools Buffers, so a captured body is often a view into a larger
    // ArrayBuffer at a non-zero offset. Ignoring that reads the wrong bytes.
    const pool = new Uint8Array(256)
    const bytes = new TextEncoder().encode(BODY)
    pool.set(bytes, 16)
    const view = pool.subarray(16, 16 + bytes.length)

    const { res, sent } = nodeResponse()
    const request = Object.assign(nodeRequest([], { 'stripe-signature': signature }), {
      rawBody: view,
    })

    await toExpressHandler(handler())(request, res)
    expect(sent.statusCode).toBe(200)
  })

  it('uses the Buffer that express.raw() leaves on req.body', async () => {
    const signature = await signStripeWebhook(BODY, SECRET, TS)
    const { res, sent } = nodeResponse()
    // express.raw() drains the stream and puts the bytes on req.body — it
    // never sets req.rawBody — so the adapter must pick them up from there.
    const request = Object.assign(nodeRequest([], { 'stripe-signature': signature }), {
      body: new TextEncoder().encode(BODY),
    })

    await toExpressHandler(handler())(request, res)
    expect(sent.statusCode).toBe(200)
  })

  it('falls back to reading the stream when nothing captured a body', async () => {
    const signature = await signStripeWebhook(BODY, SECRET, TS)
    const { res, sent } = nodeResponse()
    await toExpressHandler(handler())(nodeRequest([BODY], { 'stripe-signature': signature }), res)
    expect(sent.statusCode).toBe(200)
  })

  it('captureRawBody stashes the untouched bytes on the request', () => {
    const request = { headers: {} } as Parameters<typeof captureRawBody>[0]
    const buffer = new TextEncoder().encode(BODY)
    captureRawBody(request, null, buffer)
    expect(request.rawBody).toBe(buffer)
  })
})

describe('next adapter', () => {
  it('exposes POST, GET, and PUT bound to the same handler', async () => {
    const route = toNextRoute(handler())
    expect(Object.keys(route).sort()).toEqual(['GET', 'POST', 'PUT'])

    const signature = await signStripeWebhook(BODY, SECRET, TS)
    const request = createWebhookRequest({ body: BODY, headers: { 'stripe-signature': signature } })
    expect((await route.POST(request)).status).toBe(200)
  })

  it('routes a bodiless GET challenge through the same handler', async () => {
    const route = toNextRoute(handler())
    const response = await route.GET(createWebhookRequest({ method: 'GET' }))
    // No signature on a challenge request, so this provider rejects it — the
    // point is that the GET reaches the handler at all.
    expect(response.status).toBe(400)
  })
})

describe('h3 adapter', () => {
  it('uses the web Request an h3 v2 event carries on `req`', async () => {
    const signature = await signStripeWebhook(BODY, SECRET, TS)
    const handled = vi.fn()
    const req = createWebhookRequest({ body: BODY, headers: { 'stripe-signature': signature } })

    const response = await toH3Handler(handler({ 'charge.succeeded': handled }))({ req })
    expect(response.status).toBe(200)
    expect(handled).toHaveBeenCalledOnce()
  })

  it('reads the raw bytes off the Node stream on an h3 v1 event', async () => {
    const signature = await signStripeWebhook(BODY, SECRET, TS)
    const req = nodeRequest([BODY.slice(0, 12), BODY.slice(12)], { 'stripe-signature': signature })

    // On v1 `event.req` is the Node request too — the deprecated alias must
    // not be mistaken for a web Request.
    const response = await toH3Handler(handler({ 'charge.succeeded': vi.fn() }))({
      req,
      node: { req },
    })
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ ok: true, outcome: 'handled' })
  })

  it('maps a verification failure to a Response with its status', async () => {
    const req = nodeRequest([BODY], { 'stripe-signature': 't=1,v1=deadbeef' })
    const response = await toH3Handler(handler())({ node: { req } })
    expect(response.status).toBe(400)
    expect((await response.json()).error).toBe('timestamp_out_of_tolerance')
  })

  it('rejects an object that is not an h3 event', async () => {
    await expect(toH3Handler(handler())({})).rejects.toThrow(/h3 event/)
  })

  it('exports the Nuxt and Nitro names as the same adapter', () => {
    expect(toNuxtHandler).toBe(toH3Handler)
    expect(toNitroHandler).toBe(toH3Handler)
  })
})

describe('hono adapter', () => {
  it('unwraps the raw Request off the context', async () => {
    const signature = await signStripeWebhook(BODY, SECRET, TS)
    const raw = createWebhookRequest({ body: BODY, headers: { 'stripe-signature': signature } })
    const response = await toHonoHandler(handler())({ req: { raw } })
    expect(response.status).toBe(200)
  })
})
