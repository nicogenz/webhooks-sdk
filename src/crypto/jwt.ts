import { fromBase64, fromUtf8, utf8 } from './encoding.js'

/**
 * Just enough JWS to verify webhook bearer tokens — decode the three segments
 * and check an asymmetric signature against a JWK. Deliberately not a JWT
 * library: no claim validation lives here, because which claims matter (and
 * what failing each one should be reported as) is a per-provider decision.
 */

export interface DecodedJwt {
  header: { alg?: string; kid?: string; typ?: string; [key: string]: unknown }
  payload: Record<string, unknown>
  signature: Uint8Array
  /** `header.payload` — the exact bytes the signature covers. */
  signedContent: string
}

/**
 * Splits and decodes a compact JWT. Returns `null` on anything malformed
 * rather than throwing, so callers can map that to their own error taxonomy.
 */
export function decodeJwt(token: string): DecodedJwt | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string]

  let header: unknown
  let payload: unknown
  try {
    header = JSON.parse(fromUtf8(fromBase64(headerPart)))
    payload = JSON.parse(fromUtf8(fromBase64(payloadPart)))
  } catch {
    return null
  }

  const signature = fromBase64(signaturePart)
  if (
    !header ||
    typeof header !== 'object' ||
    !payload ||
    typeof payload !== 'object' ||
    signature.length === 0
  ) {
    return null
  }

  return {
    header: header as DecodedJwt['header'],
    payload: payload as Record<string, unknown>,
    signature,
    signedContent: `${headerPart}.${payloadPart}`,
  }
}

/**
 * The asymmetric JWS algorithms webhook providers actually use: RS256 for
 * Google's OIDC tokens, ES256 for Plaid and SendGrid. Symmetric algorithms
 * are deliberately absent — accepting HS256 against a public key is the
 * classic algorithm-confusion attack.
 */
const JWS_ALGORITHMS: Record<
  string,
  {
    importParams: RsaHashedImportParams | EcKeyImportParams
    verifyParams: AlgorithmIdentifier | EcdsaParams
  }
> = {
  RS256: {
    importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
  },
  RS384: {
    importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
    verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
  },
  RS512: {
    importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
    verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
  },
  ES256: {
    importParams: { name: 'ECDSA', namedCurve: 'P-256' },
    verifyParams: { name: 'ECDSA', hash: 'SHA-256' },
  },
  ES384: {
    importParams: { name: 'ECDSA', namedCurve: 'P-384' },
    verifyParams: { name: 'ECDSA', hash: 'SHA-384' },
  },
}

/**
 * Verifies a decoded JWT's signature against one JWK, using the token's own
 * `alg`. Returns false rather than throwing on unsupported algorithms or
 * malformed key material, mirroring `verifyEd25519`.
 */
export async function verifyJwtSignature(jwt: DecodedJwt, jwk: JsonWebKey): Promise<boolean> {
  const algorithm = jwt.header.alg ? JWS_ALGORITHMS[jwt.header.alg] : undefined
  if (!algorithm) return false

  try {
    const key = await crypto.subtle.importKey('jwk', jwk, algorithm.importParams, false, ['verify'])
    return await crypto.subtle.verify(
      algorithm.verifyParams,
      key,
      jwt.signature as BufferSource,
      utf8(jwt.signedContent) as BufferSource,
    )
  } catch {
    return false
  }
}
