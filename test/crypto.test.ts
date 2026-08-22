import { describe, expect, it } from 'vitest'
import {
  fromBase64,
  fromHex,
  hmacBase64,
  hmacHex,
  timingSafeEqual,
  timingSafeEqualHex,
  timingSafeEqualString,
  toBase64,
  toHex,
  utf8,
} from '../src/crypto/index.js'

describe('encoding', () => {
  it('round-trips hex', () => {
    const bytes = utf8('hello webhooks')
    expect(fromHex(toHex(bytes))).toEqual(bytes)
  })

  it('round-trips base64', () => {
    const bytes = utf8('hello webhooks')
    expect(fromBase64(toBase64(bytes))).toEqual(bytes)
  })

  it('accepts url-safe base64 without padding', () => {
    const bytes = new Uint8Array([251, 255, 190, 0])
    const urlSafe = toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    expect(fromBase64(urlSafe)).toEqual(bytes)
  })

  it('returns empty bytes for malformed hex rather than throwing', () => {
    expect(fromHex('zz')).toEqual(new Uint8Array(0))
    expect(fromHex('abc')).toEqual(new Uint8Array(0))
  })
})

describe('timingSafeEqual', () => {
  it('matches identical input', () => {
    expect(timingSafeEqual(utf8('abc'), utf8('abc'))).toBe(true)
  })

  it('rejects different lengths and empty input', () => {
    expect(timingSafeEqual(utf8('abc'), utf8('abcd'))).toBe(false)
    expect(timingSafeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(false)
  })

  it('rejects malformed hex instead of treating it as equal', () => {
    // Both sides decode to empty; that must not read as a match.
    expect(timingSafeEqualHex('nonsense', 'nonsense')).toBe(false)
  })

  it('compares plain token strings', () => {
    expect(timingSafeEqualString('tok_1', 'tok_1')).toBe(true)
    expect(timingSafeEqualString('tok_1', 'tok_2')).toBe(false)
  })
})

describe('hmac', () => {
  // RFC 4231 test case 1.
  it('matches the RFC 4231 SHA-256 vector', async () => {
    const key = new Uint8Array(20).fill(0x0b)
    expect(await hmacHex('SHA-256', key, 'Hi There')).toBe(
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    )
  })

  it('encodes the same digest as hex and base64', async () => {
    const hex = await hmacHex('SHA-256', 'secret', 'payload')
    const b64 = await hmacBase64('SHA-256', 'secret', 'payload')
    expect(toHex(fromBase64(b64))).toBe(hex)
  })
})
