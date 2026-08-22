import { describe, expect, it, vi } from 'vitest'
import { toBase64, utf8 } from '../src/crypto/index.js'
import { createWebhookHandler } from '../src/index.js'
import { clerk } from '../src/providers/clerk/index.js'
import { polar } from '../src/providers/polar/index.js'
import { replicate } from '../src/providers/replicate/index.js'
import { resend } from '../src/providers/resend/index.js'
import {
  parseStandardSignatureHeader,
  signStandardWebhook,
  standardWebhooks,
} from '../src/providers/standard-webhooks/index.js'
import { createWebhookRequest } from '../src/testing/index.js'

const SECRET = `whsec_${toBase64(utf8('standard-webhooks-test-key'))}`
const NOW = new Date('2026-08-20T12:00:00Z')
const TS = Math.floor(NOW.getTime() / 1000)

const BODY = JSON.stringify({ type: 'email.delivered', data: { email_id: 'e_1' } })

async function signed(
  options: {
    body?: string
    secret?: string
    id?: string
    timestamp?: number
    headerPrefix?: 'webhook' | 'svix'
  } = {},
) {
  const body = options.body ?? BODY
  const headers = await signStandardWebhook(body, options.secret ?? SECRET, {
    id: options.id ?? 'msg_2abc',
    timestamp: options.timestamp ?? TS,
    headerPrefix: options.headerPrefix,
  })
  return createWebhookRequest({ body, headers })
}

const handlerFor = (secret: string | string[] = SECRET) =>
  createWebhookHandler({
    provider: standardWebhooks({ id: 'acme', name: 'Acme', secret }),
    now: () => NOW,
  })

describe('parseStandardSignatureHeader', () => {
  it('separates symmetric from asymmetric candidates', () => {
    expect(parseStandardSignatureHeader('v1,aaa v1a,bbb v1,ccc')).toEqual({
      symmetric: ['aaa', 'ccc'],
      asymmetric: ['bbb'],
    })
  })

  it('ignores unknown versions so a future v2 fails closed rather than loudly', () => {
    expect(parseStandardSignatureHeader('v2,future')).toEqual({
      symmetric: [],
      asymmetric: [],
    })
  })

  it('tolerates empty and malformed entries', () => {
    expect(parseStandardSignatureHeader('v1, v1,ok garbage')).toEqual({
      symmetric: ['ok'],
      asymmetric: [],
    })
  })
})

describe('standard webhooks verification', () => {
  it('accepts a correctly signed request', async () => {
    const result = await handlerFor().process(await signed())
    expect(result.ok).toBe(true)
    expect(result.event?.type).toBe('email.delivered')
    expect(result.event?.provider).toBe('acme')
  })

  it('accepts the legacy svix-* header names', async () => {
    const result = await handlerFor().process(await signed({ headerPrefix: 'svix' }))
    expect(result.ok).toBe(true)
  })

  it('uses webhook-id as the event id, not anything in the body', async () => {
    const result = await handlerFor().process(await signed({ id: 'msg_canonical' }))
    expect(result.event?.id).toBe('msg_canonical')
  })

  it('derives the timestamp from the header', async () => {
    const result = await handlerFor().process(await signed({ timestamp: TS - 60 }))
    expect(result.event?.timestamp).toEqual(new Date((TS - 60) * 1000))
  })

  it('rejects a wrong secret', async () => {
    const wrong = `whsec_${toBase64(utf8('not-the-key'))}`
    const result = await handlerFor().process(await signed({ secret: wrong }))
    expect(result.error?.code).toBe('invalid_signature')
  })

  it('rejects a body tampered with after signing', async () => {
    const headers = await signStandardWebhook(BODY, SECRET, { id: 'msg_1', timestamp: TS })
    const result = await handlerFor().process(
      createWebhookRequest({ body: BODY.replace('e_1', 'e_2'), headers }),
    )
    expect(result.error?.code).toBe('invalid_signature')
  })

  it('rejects a signature bound to a different message id', async () => {
    // The id is inside the signed material, so swapping it must invalidate.
    const headers = await signStandardWebhook(BODY, SECRET, { id: 'msg_1', timestamp: TS })
    headers['webhook-id'] = 'msg_other'
    const result = await handlerFor().process(createWebhookRequest({ body: BODY, headers }))
    expect(result.error?.code).toBe('invalid_signature')
  })

  it('rejects a stale timestamp', async () => {
    const result = await handlerFor().process(await signed({ timestamp: TS - 3600 }))
    expect(result.error?.code).toBe('timestamp_out_of_tolerance')
  })

  it('rejects a timestamp too far in the future', async () => {
    const result = await handlerFor().process(await signed({ timestamp: TS + 3600 }))
    expect(result.error?.code).toBe('timestamp_out_of_tolerance')
  })

  it('names the missing headers', async () => {
    const result = await handlerFor().process(createWebhookRequest({ body: BODY }))
    expect(result.error?.code).toBe('missing_signature')
    expect(result.error?.message).toContain('webhook-id')
    expect(result.error?.message).toContain('webhook-signature')
  })

  it('rejects a non-integer timestamp', async () => {
    const headers = await signStandardWebhook(BODY, SECRET, { timestamp: TS })
    headers['webhook-timestamp'] = 'not-a-number'
    const result = await handlerFor().process(createWebhookRequest({ body: BODY, headers }))
    expect(result.error?.code).toBe('missing_signature')
  })

  it('accepts either secret during a rotation', async () => {
    const older = `whsec_${toBase64(utf8('older-key'))}`
    const handler = handlerFor([older, SECRET])
    expect((await handler.process(await signed({ secret: older }))).ok).toBe(true)
    expect((await handler.process(await signed({ secret: SECRET }))).ok).toBe(true)
  })

  it('accepts any matching candidate when several are sent', async () => {
    const headers = await signStandardWebhook(BODY, SECRET, { id: 'msg_1', timestamp: TS })
    const real = headers['webhook-signature'] as string
    headers['webhook-signature'] = `v1,${toBase64(utf8('bogus-signature-value'))} ${real}`
    const result = await handlerFor().process(createWebhookRequest({ body: BODY, headers }))
    expect(result.ok).toBe(true)
  })

  it('fails configuration on a secret that is not valid base64', async () => {
    const handler = createWebhookHandler({
      provider: standardWebhooks({ id: 'acme', secret: 'whsec_!!!not-base64!!!' }),
      now: () => NOW,
    })
    const result = await handler.process(await signed())
    expect(result.error?.code).toBe('invalid_configuration')
  })

  it('fails configuration when neither a secret nor a public key is given', async () => {
    const handler = createWebhookHandler({ provider: standardWebhooks({ id: 'acme' }) })
    const result = await handler.process(await signed())
    expect(result.error?.code).toBe('invalid_configuration')
  })

  it('reports a missing event-name field rather than guessing', async () => {
    const body = JSON.stringify({ data: {} })
    const result = await handlerFor().process(await signed({ body }))
    expect(result.error?.code).toBe('invalid_payload')
    expect(result.error?.message).toContain('"type"')
  })
})

describe('asymmetric v1a signatures', () => {
  it('verifies an Ed25519 signature against a whpk_ public key', async () => {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const rawPublic = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))

    const id = 'msg_ed25519'
    const signature = new Uint8Array(
      await crypto.subtle.sign('Ed25519', pair.privateKey, utf8(`${id}.${TS}.${BODY}`)),
    )

    const handler = createWebhookHandler({
      provider: standardWebhooks({
        id: 'acme',
        publicKey: `whpk_${toBase64(rawPublic)}`,
      }),
      now: () => NOW,
    })

    const result = await handler.process(
      createWebhookRequest({
        body: BODY,
        headers: {
          'webhook-id': id,
          'webhook-timestamp': String(TS),
          'webhook-signature': `v1a,${toBase64(signature)}`,
        },
      }),
    )

    expect(result.error).toBeUndefined()
    expect(result.ok).toBe(true)
  })

  it('rejects an Ed25519 signature from the wrong key', async () => {
    const signer = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const other = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const rawPublic = new Uint8Array(await crypto.subtle.exportKey('raw', other.publicKey))

    const id = 'msg_ed25519'
    const signature = new Uint8Array(
      await crypto.subtle.sign('Ed25519', signer.privateKey, utf8(`${id}.${TS}.${BODY}`)),
    )

    const handler = createWebhookHandler({
      provider: standardWebhooks({ id: 'acme', publicKey: `whpk_${toBase64(rawPublic)}` }),
      now: () => NOW,
    })

    const result = await handler.process(
      createWebhookRequest({
        body: BODY,
        headers: {
          'webhook-id': id,
          'webhook-timestamp': String(TS),
          'webhook-signature': `v1a,${toBase64(signature)}`,
        },
      }),
    )

    expect(result.error?.code).toBe('invalid_signature')
  })
})

describe('vendor wrappers', () => {
  it('resend verifies over svix-* headers and dispatches', async () => {
    const handled = vi.fn()
    const handler = createWebhookHandler({
      provider: resend({ secret: SECRET }),
      now: () => NOW,
      on: { 'email.delivered': handled },
    })

    const result = await handler.process(await signed({ headerPrefix: 'svix' }))
    expect(result.event?.provider).toBe('resend')
    expect(handled).toHaveBeenCalledOnce()
  })

  it('clerk and polar reuse the same scheme with their own slug', async () => {
    for (const [provider, slug] of [
      [clerk({ secret: SECRET }), 'clerk'],
      [polar({ secret: SECRET }), 'polar'],
    ] as const) {
      const result = await createWebhookHandler({ provider, now: () => NOW }).process(
        await signed(),
      )
      expect(result.ok).toBe(true)
      expect(result.event?.provider).toBe(slug)
    }
  })

  it('replicate takes its event name from status, not type', async () => {
    const body = JSON.stringify({ id: 'pred_1', status: 'succeeded', output: [] })
    const handled = vi.fn()
    const handler = createWebhookHandler({
      provider: replicate({ secret: SECRET }),
      now: () => NOW,
      on: { succeeded: handled },
    })

    const result = await handler.process(await signed({ body }))
    expect(result.event?.type).toBe('succeeded')
    expect(handled).toHaveBeenCalledOnce()
  })
})
