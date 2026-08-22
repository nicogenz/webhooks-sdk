const encoder = new TextEncoder()
const decoder = new TextDecoder()

export function utf8(value: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(value)
}

export function fromUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes)
}

export function toBytes(value: string | Uint8Array | ArrayBuffer): Uint8Array {
  if (typeof value === 'string') return utf8(value)
  if (value instanceof Uint8Array) return value
  return new Uint8Array(value)
}

export function toHex(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0')
  return out
}

export function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  if (clean.length % 2 !== 0) return new Uint8Array(0)
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    const byte = Number.parseInt(clean.substr(i * 2, 2), 16)
    if (Number.isNaN(byte)) return new Uint8Array(0)
    bytes[i] = byte
  }
  return bytes
}

export function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

/** URL-safe base64 without padding — the JWT segment encoding. */
export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  // Accepts standard and URL-safe base64, with or without padding.
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=')
  try {
    const binary = atob(padded)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
    return bytes
  } catch {
    return new Uint8Array(0)
  }
}

/**
 * Compares two byte sequences without leaking, through timing, how many
 * leading bytes matched. Length differences are not concealed — signature
 * lengths are fixed per algorithm and public knowledge.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length || a.length === 0) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number)
  return diff === 0
}

/** Timing-safe comparison of two hex-encoded digests. */
export function timingSafeEqualHex(a: string, b: string): boolean {
  return timingSafeEqual(fromHex(a.trim()), fromHex(b.trim()))
}

/** Timing-safe comparison of two base64-encoded digests. */
export function timingSafeEqualBase64(a: string, b: string): boolean {
  return timingSafeEqual(fromBase64(a.trim()), fromBase64(b.trim()))
}

/** Timing-safe comparison of two plain strings (shared-secret tokens). */
export function timingSafeEqualString(a: string, b: string): boolean {
  return timingSafeEqual(utf8(a), utf8(b))
}
