import { toBytes } from './encoding.js'

/**
 * Verifies an Ed25519 signature. Used by Discord interactions and a growing
 * number of providers that want verification without a shared secret.
 *
 * Requires Web Crypto Ed25519 support: Node 22+, Deno, Bun, and Cloudflare
 * Workers all ship it. Returns false rather than throwing on malformed input.
 */
export async function verifyEd25519(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: string | Uint8Array,
): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      publicKey as BufferSource,
      { name: 'Ed25519' },
      false,
      ['verify'],
    )
    return await crypto.subtle.verify(
      'Ed25519',
      key,
      signature as BufferSource,
      toBytes(message) as BufferSource,
    )
  } catch {
    return false
  }
}
