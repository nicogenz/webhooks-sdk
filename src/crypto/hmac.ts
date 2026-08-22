import { toBase64, toBytes, toHex } from './encoding.js'

export type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512'

export type SecretInput = string | Uint8Array

async function importKey(secret: SecretInput, algorithm: HashAlgorithm): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    toBytes(secret) as BufferSource,
    { name: 'HMAC', hash: algorithm },
    false,
    ['sign'],
  )
}

/** Raw HMAC digest. */
export async function hmac(
  algorithm: HashAlgorithm,
  secret: SecretInput,
  message: string | Uint8Array,
): Promise<Uint8Array> {
  const key = await importKey(secret, algorithm)
  const signature = await crypto.subtle.sign('HMAC', key, toBytes(message) as BufferSource)
  return new Uint8Array(signature)
}

/** HMAC digest, hex-encoded — the most common webhook encoding. */
export async function hmacHex(
  algorithm: HashAlgorithm,
  secret: SecretInput,
  message: string | Uint8Array,
): Promise<string> {
  return toHex(await hmac(algorithm, secret, message))
}

/** HMAC digest, base64-encoded — used by Shopify, Square, DocuSign, Xero. */
export async function hmacBase64(
  algorithm: HashAlgorithm,
  secret: SecretInput,
  message: string | Uint8Array,
): Promise<string> {
  return toBase64(await hmac(algorithm, secret, message))
}
