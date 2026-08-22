import { describe, expect, it } from 'vitest'
import { digestHex } from '../src/crypto/index.js'
import { createWebhookHandler, toRawWebhook } from '../src/index.js'
import {
  signTwilioWebhook,
  TWILIO_SIGNATURE_HEADER,
  twilio,
  verifyTwilioWebhook,
} from '../src/providers/twilio/index.js'
import { createWebhookRequest } from '../src/testing/index.js'

const AUTH_TOKEN = 'test_auth_token'
const ENDPOINT = 'https://example.com/webhooks/twilio'

const SMS_PARAMS = {
  MessageSid: 'SM1234567890abcdef',
  SmsSid: 'SM1234567890abcdef',
  AccountSid: 'AC123',
  From: '+15551234567',
  To: '+15557654321',
  Body: 'Hello, world & goodbye',
  SmsStatus: 'received',
  NumMedia: '0',
}

function formBody(params: Record<string, string>): string {
  return new URLSearchParams(params).toString()
}

async function signedRequest(
  overrides: {
    params?: Record<string, string>
    /** The URL the signature is computed for. */
    signedUrl?: string
    /** The URL the request is actually sent to. */
    requestUrl?: string
    authToken?: string
    body?: string
  } = {},
) {
  const params = overrides.params ?? SMS_PARAMS
  const signedUrl = overrides.signedUrl ?? ENDPOINT
  const signature = await signTwilioWebhook(signedUrl, params, overrides.authToken ?? AUTH_TOKEN)
  return createWebhookRequest({
    body: overrides.body ?? formBody(params),
    url: overrides.requestUrl ?? signedUrl,
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      [TWILIO_SIGNATURE_HEADER]: signature,
    },
  })
}

const handlerFor = (options: Partial<Parameters<typeof twilio>[0]> = {}) =>
  createWebhookHandler({ provider: twilio({ authToken: AUTH_TOKEN, ...options }) })

describe('twilio signature algorithm', () => {
  it("reproduces the worked example from Twilio's security documentation", async () => {
    // Pinned against Twilio's docs, not this SDK — a change that breaks this
    // breaks interop, not a test fixture.
    const signature = await signTwilioWebhook(
      'https://mycompany.com/myapp.php?foo=1&bar=2',
      {
        CallSid: 'CA1234567890ABCDE',
        Caller: '+12349013030',
        Digits: '1234',
        From: '+12349013030',
        To: '+18005551212',
      },
      '12345',
    )
    expect(signature).toBe('0/KCTR6DLpKmkAf8muzZqo1nDgQ=')
  })

  it('sorts parameters by key before concatenating', async () => {
    // Same params in a different insertion order must sign identically.
    const forward = await signTwilioWebhook(ENDPOINT, { Alpha: '1', Beta: '2' }, AUTH_TOKEN)
    const reversed = await signTwilioWebhook(ENDPOINT, { Beta: '2', Alpha: '1' }, AUTH_TOKEN)
    expect(forward).toBe(reversed)
  })
})

describe('twilio form-encoded verification', () => {
  it('accepts a correctly signed request and derives the event', async () => {
    const result = await handlerFor().process(await signedRequest())
    expect(result.ok).toBe(true)
    expect(result.event?.type).toBe('message.received')
    expect(result.event?.id).toBe('SM1234567890abcdef:message.received')
    expect(result.event?.payload).toMatchObject({ Body: 'Hello, world & goodbye' })
  })

  it('rejects a signature made with the wrong auth token', async () => {
    const result = await handlerFor().process(await signedRequest({ authToken: 'wrong' }))
    expect(result.error?.code).toBe('invalid_signature')
    expect(result.error?.status).toBe(401)
  })

  it('rejects a body tampered with after signing', async () => {
    const signature = await signTwilioWebhook(ENDPOINT, SMS_PARAMS, AUTH_TOKEN)
    const tampered = formBody({ ...SMS_PARAMS, Body: 'transfer all funds' })
    const result = await handlerFor().process(
      createWebhookRequest({
        body: tampered,
        url: ENDPOINT,
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          [TWILIO_SIGNATURE_HEADER]: signature,
        },
      }),
    )
    expect(result.error?.code).toBe('invalid_signature')
  })

  it('rejects a request signed for a different URL', async () => {
    // The URL is inside the signed material — this is the point of family 7.
    const result = await handlerFor().process(
      await signedRequest({
        signedUrl: 'https://evil.example.com/webhooks/twilio',
        requestUrl: ENDPOINT,
      }),
    )
    expect(result.error?.code).toBe('invalid_signature')
  })

  it('rejects a request with no signature header', async () => {
    const result = await handlerFor().process(
      createWebhookRequest({
        body: formBody(SMS_PARAMS),
        url: ENDPOINT,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
      }),
    )
    expect(result.error?.code).toBe('missing_signature')
  })

  it('accepts either token during a rotation', async () => {
    const handler = handlerFor({ authToken: ['old_token', 'new_token'] })
    expect((await handler.process(await signedRequest({ authToken: 'old_token' }))).ok).toBe(true)
    expect((await handler.process(await signedRequest({ authToken: 'new_token' }))).ok).toBe(true)
  })
})

describe('twilio URL resolution', () => {
  it('verifies against the configured URL when a proxy rewrote the request', async () => {
    // Twilio signed the public URL; the app sees the internal one.
    const handler = handlerFor({ url: ENDPOINT })
    const result = await handler.process(
      await signedRequest({
        signedUrl: ENDPOINT,
        requestUrl: 'http://internal:3000/webhooks/twilio',
      }),
    )
    expect(result.ok).toBe(true)
  })

  it('carries the request query over onto a static configured URL', async () => {
    // Twilio appends parameters to the URL it was configured with and signs
    // the result, so a static override must not strip them.
    const handler = handlerFor({ url: ENDPOINT })
    const result = await handler.process(
      await signedRequest({
        signedUrl: `${ENDPOINT}?AccountSid=AC123`,
        requestUrl: 'http://internal:3000/webhooks/twilio?AccountSid=AC123',
      }),
    )
    expect(result.ok).toBe(true)
  })

  it('resolves the URL through a function for multi-tenant endpoints', async () => {
    const handler = handlerFor({
      url: (raw) => `https://example.com${new URL(raw.url ?? '').pathname}`,
    })
    const result = await handler.process(
      await signedRequest({
        signedUrl: ENDPOINT,
        requestUrl: 'https://ignored.example.com/webhooks/twilio',
      }),
    )
    expect(result.ok).toBe(true)
  })

  it('fails as configuration when the request URL is a bare path', async () => {
    // Node's req.url is a path; verifying against it would fail every
    // delivery with "bad signature", which is undebuggable.
    const result = await handlerFor().process({
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        [TWILIO_SIGNATURE_HEADER]: await signTwilioWebhook(ENDPOINT, SMS_PARAMS, AUTH_TOKEN),
      },
      body: formBody(SMS_PARAMS),
      url: '/webhooks/twilio',
    })
    expect(result.error?.code).toBe('invalid_configuration')
  })

  it('fails as configuration when no URL exists at all', async () => {
    const result = await handlerFor().process({
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        [TWILIO_SIGNATURE_HEADER]: await signTwilioWebhook(ENDPOINT, SMS_PARAMS, AUTH_TOKEN),
      },
      body: formBody(SMS_PARAMS),
    })
    expect(result.error?.code).toBe('invalid_configuration')
  })
})

describe('twilio JSON (bodySHA256) flow', () => {
  async function jsonRequest(overrides: { tamper?: boolean; authToken?: string } = {}) {
    const body = JSON.stringify({ EventType: 'onMessageAdded', Sid: 'IM123', Body: 'hi' })
    const url = `${ENDPOINT}?bodySHA256=${await digestHex('SHA-256', body)}`
    const signature = await signTwilioWebhook(url, {}, overrides.authToken ?? AUTH_TOKEN)
    return createWebhookRequest({
      body: overrides.tamper ? body.replace('hi', 'bye') : body,
      url,
      headers: { [TWILIO_SIGNATURE_HEADER]: signature },
    })
  }

  it('accepts a signed JSON webhook and parses it', async () => {
    const result = await handlerFor().process(await jsonRequest())
    expect(result.ok).toBe(true)
    expect(result.event?.type).toBe('onMessageAdded')
    expect(result.event?.id).toBe('IM123:onMessageAdded')
  })

  it('rejects a JSON body tampered with after signing', async () => {
    // The recomputed body hash changes the rebuilt URL, so the HMAC fails.
    const result = await handlerFor().process(await jsonRequest({ tamper: true }))
    expect(result.error?.code).toBe('invalid_signature')
  })

  it('rejects the wrong token even when the body hash matches', async () => {
    const result = await handlerFor().process(await jsonRequest({ authToken: 'wrong' }))
    expect(result.error?.code).toBe('invalid_signature')
  })
})

describe('twilio event derivation', () => {
  it('derives call events from CallStatus', async () => {
    const params = { CallSid: 'CA999', CallStatus: 'completed', CallDuration: '32' }
    const result = await handlerFor().process(await signedRequest({ params }))
    expect(result.event?.type).toBe('call.completed')
    expect(result.event?.id).toBe('CA999:call.completed')
  })

  it('uses EventType verbatim when a product sends one', async () => {
    const params = { EventType: 'task.created', Sid: 'WT1' }
    const result = await handlerFor().process(await signedRequest({ params }))
    expect(result.event?.type).toBe('task.created')
  })

  it('gives each status callback for one message a distinct id', async () => {
    const sent = await handlerFor().process(
      await signedRequest({ params: { MessageSid: 'SM1', MessageStatus: 'sent' } }),
    )
    const delivered = await handlerFor().process(
      await signedRequest({ params: { MessageSid: 'SM1', MessageStatus: 'delivered' } }),
    )
    expect(sent.event?.id).not.toBe(delivered.event?.id)
  })

  it('falls back to unknown with a blank id rather than guessing', async () => {
    const result = await handlerFor().process(await signedRequest({ params: { Foo: 'bar' } }))
    expect(result.event?.type).toBe('unknown')
    expect(result.event?.id).toBe('')
  })
})

describe('twilio standalone verification', () => {
  it('verifies a GET-style webhook whose parameters live in the query', async () => {
    const url = `${ENDPOINT}?CallSid=CA1&CallStatus=ringing`
    const raw = await toRawWebhook({
      headers: { [TWILIO_SIGNATURE_HEADER]: await signTwilioWebhook(url, {}, AUTH_TOKEN) },
      body: '',
      method: 'GET',
      url,
    })
    await expect(verifyTwilioWebhook(raw, { authToken: AUTH_TOKEN })).resolves.toBeUndefined()
  })
})
