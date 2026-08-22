import { beforeAll, describe, expect, it, vi } from 'vitest'
import { toHex } from '../src/crypto/index.js'
import { createWebhookHandler } from '../src/index.js'
import {
  DISCORD_SIGNATURE_HEADER,
  DISCORD_TIMESTAMP_HEADER,
  discord,
  signDiscordWebhook,
} from '../src/providers/discord/index.js'
import { createWebhookRequest } from '../src/testing/index.js'

const NOW = new Date('2026-08-20T12:00:00Z')
const TS = Math.floor(NOW.getTime() / 1000)

let keys: CryptoKeyPair
let otherKeys: CryptoKeyPair
let publicKey: string

beforeAll(async () => {
  keys = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair
  otherKeys = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair
  publicKey = toHex(new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey)))
})

async function signed(
  body: object | string,
  options: { key?: CryptoKey; timestamp?: number } = {},
) {
  const text = typeof body === 'string' ? body : JSON.stringify(body)
  const headers = await signDiscordWebhook(
    text,
    options.key ?? keys.privateKey,
    options.timestamp ?? TS,
  )
  return createWebhookRequest({ body: text, headers })
}

const handlerFor = (overrides: Parameters<typeof discord>[0] = { publicKey }) =>
  createWebhookHandler({ provider: discord(overrides), now: () => NOW })

describe('discord verification', () => {
  it('accepts a correctly signed interaction', async () => {
    const result = await handlerFor().process(
      await signed({ id: 'int_1', type: 2, data: { name: 'ping' } }),
    )
    expect(result.ok).toBe(true)
    expect(result.event?.type).toBe('application_command')
    expect(result.event?.id).toBe('int_1')
  })

  it('signs timestamp and body with no separator between them', async () => {
    // A separator would change the signed material; this pins the exact format.
    const body = JSON.stringify({ id: 'x', type: 2 })
    const headers = await signDiscordWebhook(body, keys.privateKey, TS)
    const shifted = { ...headers, [DISCORD_TIMESTAMP_HEADER]: String(TS + 1) }
    const result = await handlerFor().process(createWebhookRequest({ body, headers: shifted }))
    expect(result.error?.code).toBe('invalid_signature')
  })

  it('rejects a signature from a different key', async () => {
    const result = await handlerFor().process(
      await signed({ id: 'x', type: 2 }, { key: otherKeys.privateKey }),
    )
    expect(result.error?.code).toBe('invalid_signature')
  })

  it('rejects a tampered body', async () => {
    const body = JSON.stringify({ id: 'x', type: 2 })
    const headers = await signDiscordWebhook(body, keys.privateKey, TS)
    const result = await handlerFor().process(
      createWebhookRequest({ body: body.replace('"x"', '"y"'), headers }),
    )
    expect(result.error?.code).toBe('invalid_signature')
  })

  it('names the missing headers', async () => {
    const result = await handlerFor().process(createWebhookRequest({ body: { type: 2 } }))
    expect(result.error?.code).toBe('missing_signature')
    expect(result.error?.message).toContain(DISCORD_SIGNATURE_HEADER)
    expect(result.error?.message).toContain(DISCORD_TIMESTAMP_HEADER)
  })

  it('accepts any key during a rotation', async () => {
    const otherPublic = toHex(
      new Uint8Array(await crypto.subtle.exportKey('raw', otherKeys.publicKey)),
    )
    const handler = handlerFor({ publicKey: [otherPublic, publicKey] })
    expect((await handler.process(await signed({ id: 'a', type: 2 }))).ok).toBe(true)
    expect(
      (await handler.process(await signed({ id: 'b', type: 2 }, { key: otherKeys.privateKey }))).ok,
    ).toBe(true)
  })

  it('rejects a public key that is not 32 bytes of hex', async () => {
    for (const key of ['deadbeef', 'not-hex-at-all', '']) {
      const result = await handlerFor({ publicKey: key }).process(await signed({ type: 2 }))
      expect(result.error?.code).toBe('invalid_configuration')
    }
  })

  it('enforces a replay window by default, with tolerance: 0 as the opt-out', async () => {
    const stale = await signed({ id: 'x', type: 2 }, { timestamp: TS - 86_400 })
    // The timestamp is inside the signed material precisely so it can be
    // checked; without a window a captured interaction verifies forever.
    expect((await handlerFor().process(stale)).error?.code).toBe('timestamp_out_of_tolerance')
    // Discord's own reference library enforces no window, so opting out stays possible.
    const unguarded = handlerFor({ publicKey, tolerance: 0 })
    expect((await unguarded.process(stale)).ok).toBe(true)
  })
})

describe('discord handshake ordering', () => {
  it('answers a correctly signed PING with PONG', async () => {
    const response = await handlerFor().fetch(await signed({ type: 1 }))
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ type: 1 })
  })

  it('rejects a PING whose signature is invalid', async () => {
    // Discord probes new endpoints exactly this way and refuses to save the
    // URL unless the probe is rejected. Answering PONG here would break setup.
    const response = await handlerFor().fetch(
      await signed({ type: 1 }, { key: otherKeys.privateKey }),
    )
    expect(response.status).toBe(401)
    expect(await response.json()).toMatchObject({ error: 'invalid_signature' })
  })

  it('rejects a PING carrying a garbage signature header', async () => {
    const response = await handlerFor().fetch(
      createWebhookRequest({
        body: { type: 1 },
        headers: {
          [DISCORD_SIGNATURE_HEADER]: '00'.repeat(64),
          [DISCORD_TIMESTAMP_HEADER]: String(TS),
        },
      }),
    )
    expect(response.status).toBe(401)
  })

  it('does not dispatch a PING to handlers', async () => {
    const onEvent = vi.fn()
    const handler = createWebhookHandler({
      provider: discord({ publicKey }),
      now: () => NOW,
      onEvent,
    })
    const result = await handler.process(await signed({ type: 1 }))
    expect(result.outcome).toBe('handshake')
    expect(onEvent).not.toHaveBeenCalled()
  })

  it('verifies exactly once for a non-PING delivery', async () => {
    // The handshake path must not cause a second signature check.
    const provider = discord({ publicKey })
    const verify = vi.spyOn(provider, 'verify')
    const handler = createWebhookHandler({ provider, now: () => NOW })

    await handler.process(await signed({ id: 'x', type: 2 }))
    expect(verify).toHaveBeenCalledOnce()
  })
})

describe('discord webhook events mode', () => {
  const eventsHandler = () => handlerFor({ publicKey, mode: 'events' })

  it('answers a type 0 PING with 204, not PONG', async () => {
    const response = await eventsHandler().fetch(await signed({ type: 0 }))
    expect(response.status).toBe(204)
  })

  it('takes the event name from event.type', async () => {
    const result = await eventsHandler().process(
      await signed({
        version: 1,
        type: 1,
        event: { type: 'APPLICATION_AUTHORIZED', timestamp: '2026-08-20T12:00:00.000Z' },
      }),
    )
    expect(result.ok).toBe(true)
    expect(result.event?.type).toBe('APPLICATION_AUTHORIZED')
    expect(result.event?.id).toBe('APPLICATION_AUTHORIZED:2026-08-20T12:00:00.000Z')
  })

  it('gives a redelivery the same id so dedup works without a delivery header', async () => {
    const body = {
      version: 1,
      type: 1,
      event: { type: 'ENTITLEMENT_CREATE', timestamp: '2026-08-20T11:59:00.000Z' },
    }
    const first = await eventsHandler().process(await signed(body, { timestamp: TS }))
    const second = await eventsHandler().process(await signed(body, { timestamp: TS + 30 }))
    expect(first.event?.id).toBe(second.event?.id)
  })

  it('reports a malformed event payload', async () => {
    const result = await eventsHandler().process(await signed({ version: 1, type: 1 }))
    expect(result.error?.code).toBe('invalid_payload')
  })

  it('does not treat interactions-mode type 1 as a PING', async () => {
    // Type 1 means "event" here, not PING — the products disagree.
    const result = await eventsHandler().process(
      await signed({ version: 1, type: 1, event: { type: 'X', timestamp: '2026-01-01' } }),
    )
    expect(result.outcome).not.toBe('handshake')
  })
})
