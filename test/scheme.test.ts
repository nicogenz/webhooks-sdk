import { describe, expect, it } from 'vitest'
import { hmacBase64, hmacHex, utf8 } from '../src/crypto/index.js'
import {
  assertWithinTolerance,
  ConfigurationError,
  createHmacProvider,
  createWebhookHandler,
  MissingSignatureError,
  matchesAnyHmac,
  resolveSecrets,
  TimestampToleranceError,
} from '../src/index.js'
import { createWebhookRequest } from '../src/testing/index.js'

const NOW = new Date('2026-08-20T12:00:00Z')
const TS = Math.floor(NOW.getTime() / 1000)

describe('resolveSecrets', () => {
  it('accepts a single secret or an array', () => {
    expect(resolveSecrets('a', 'p')).toEqual([utf8('a')])
    expect(resolveSecrets(['a', 'b'], 'p')).toEqual([utf8('a'), utf8('b')])
  })

  it('rejects an empty, undefined, or all-blank secret', () => {
    const blank: (string | string[] | undefined)[] = [undefined, '', [], ['', '']]
    for (const value of blank) {
      expect(() => resolveSecrets(value, 'p')).toThrow(ConfigurationError)
    }
  })

  it('applies a custom decoder', () => {
    expect(resolveSecrets('ab', 'p', () => new Uint8Array([1, 2]))).toEqual([
      new Uint8Array([1, 2]),
    ])
  })
})

describe('assertWithinTolerance', () => {
  const ctx = (tolerance: number) => ({ now: NOW, tolerance })

  it('accepts a timestamp inside the window, in both directions', () => {
    expect(() => assertWithinTolerance(TS - 299, ctx(300), 'p')).not.toThrow()
    expect(() => assertWithinTolerance(TS + 299, ctx(300), 'p')).not.toThrow()
  })

  it('rejects a timestamp outside the window, in both directions', () => {
    expect(() => assertWithinTolerance(TS - 301, ctx(300), 'p')).toThrow(TimestampToleranceError)
    expect(() => assertWithinTolerance(TS + 301, ctx(300), 'p')).toThrow(TimestampToleranceError)
  })

  it('rejects a non-finite timestamp instead of silently passing it', () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(() => assertWithinTolerance(bad, ctx(300), 'p')).toThrow(TimestampToleranceError)
    }
  })

  it('treats a tolerance of 0 as "no replay window"', () => {
    // Family 1 signs no timestamp, so there is nothing to bound.
    expect(() => assertWithinTolerance(0, ctx(0), 'p')).not.toThrow()
  })
})

describe('matchesAnyHmac', () => {
  const base = { content: 'payload', secrets: [utf8('s1')] }

  it('matches a hex digest', async () => {
    const candidate = await hmacHex('SHA-256', 's1', 'payload')
    expect(await matchesAnyHmac({ ...base, candidates: [candidate], encoding: 'hex' })).toBe(true)
  })

  it('matches a base64 digest', async () => {
    const candidate = await hmacBase64('SHA-256', 's1', 'payload')
    expect(await matchesAnyHmac({ ...base, candidates: [candidate], encoding: 'base64' })).toBe(
      true,
    )
  })

  it('matches when any of several secrets works', async () => {
    const candidate = await hmacHex('SHA-256', 's2', 'payload')
    expect(
      await matchesAnyHmac({
        content: 'payload',
        secrets: [utf8('s1'), utf8('s2')],
        candidates: [candidate],
        encoding: 'hex',
      }),
    ).toBe(true)
  })

  it('matches when any of several candidates works', async () => {
    const candidate = await hmacHex('SHA-256', 's1', 'payload')
    expect(
      await matchesAnyHmac({ ...base, candidates: ['deadbeef', candidate], encoding: 'hex' }),
    ).toBe(true)
  })

  it('honours a non-default algorithm', async () => {
    const sha512 = await hmacHex('SHA-512', 's1', 'payload')
    expect(
      await matchesAnyHmac({
        ...base,
        candidates: [sha512],
        encoding: 'hex',
        algorithm: 'SHA-512',
      }),
    ).toBe(true)
    expect(await matchesAnyHmac({ ...base, candidates: [sha512], encoding: 'hex' })).toBe(false)
  })

  it('returns false for no candidates and for a wrong digest', async () => {
    expect(await matchesAnyHmac({ ...base, candidates: [], encoding: 'hex' })).toBe(false)
    expect(await matchesAnyHmac({ ...base, candidates: ['00'], encoding: 'hex' })).toBe(false)
  })
})

describe('createHmacProvider', () => {
  // A minimal family-1 provider, the shape a contributor would write.
  const acme = (secret: string | string[]) =>
    createHmacProvider({
      id: 'acme',
      name: 'Acme',
      secret,
      encoding: 'hex',
      extract: (raw) => {
        const header = raw.header('x-acme-signature')
        if (!header) throw new MissingSignatureError('Missing x-acme-signature')
        return { candidates: [header] }
      },
      content: (_material, raw) => raw.text(),
      event: (raw) => ({
        id: raw.header('x-acme-id') ?? 'unknown',
        provider: 'acme',
        type: raw.json<{ event: string }>().event,
        timestamp: NOW,
        payload: raw.json(),
        raw,
      }),
    })

  const body = JSON.stringify({ event: 'thing.happened' })

  const request = async (secret: string) =>
    createWebhookRequest({
      body,
      headers: {
        'x-acme-signature': await hmacHex('SHA-256', secret, body),
        'x-acme-id': 'a_1',
      },
    })

  it('verifies and dispatches a custom provider in ~15 lines of description', async () => {
    const handler = createWebhookHandler({ provider: acme('s1'), now: () => NOW })
    const result = await handler.process(await request('s1'))
    expect(result.ok).toBe(true)
    expect(result.event).toMatchObject({ id: 'a_1', provider: 'acme', type: 'thing.happened' })
  })

  it('inherits rotation, timing-safe compare, and the error taxonomy', async () => {
    const handler = createWebhookHandler({ provider: acme(['old', 's1']), now: () => NOW })
    expect((await handler.process(await request('old'))).ok).toBe(true)
    expect((await handler.process(await request('s1'))).ok).toBe(true)
    expect((await handler.process(await request('wrong'))).error?.code).toBe('invalid_signature')
    expect((await handler.process(createWebhookRequest({ body }))).error?.code).toBe(
      'missing_signature',
    )
  })

  it('reports no replay window when the scheme signs no timestamp', () => {
    expect(acme('s1').tolerance).toBe(0)
  })
})
