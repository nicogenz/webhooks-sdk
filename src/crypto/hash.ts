import { toBytes, toHex } from './encoding.js'

export type DigestAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512'

/** Plain (unkeyed) digest of a message. */
export async function digest(
  algorithm: DigestAlgorithm,
  data: string | Uint8Array,
): Promise<Uint8Array> {
  const bytes = await crypto.subtle.digest(algorithm, toBytes(data) as BufferSource)
  return new Uint8Array(bytes)
}

/** Plain digest, hex-encoded — Twilio's `bodySHA256` uses this. */
export async function digestHex(
  algorithm: DigestAlgorithm,
  data: string | Uint8Array,
): Promise<string> {
  return toHex(await digest(algorithm, data))
}
