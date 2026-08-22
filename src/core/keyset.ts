import { KeyUnavailableError } from './errors.js'

/**
 * Key material for the JWT and certificate families (5 and 6 in
 * INTEGRATIONS.md). Unlike an HMAC secret, these keys live on the provider's
 * side, rotate without notice, and have to be fetched — which drags a network
 * dependency and a cache into what is otherwise pure computation. This
 * interface keeps that pluggable: the built-in implementation below covers the
 * common case, and anything else (a KV-backed cache, a pinned key file) is a
 * one-method object.
 */
export interface KeySet {
  /**
   * Returns the JWK for a key id, or `undefined` when no key matches. `now`
   * exists so cache expiry is testable without a wall clock.
   */
  get(kid: string, now?: Date): Promise<Jwk | undefined>
}

/**
 * A key as it appears in a JWKS. The lib type `JsonWebKey` models only what
 * `crypto.subtle.importKey` reads, so the JOSE identification fields are
 * added here — `kid` is how a token names its key.
 */
export interface Jwk extends JsonWebKey {
  kid?: string
  ext?: boolean
  [parameter: string]: unknown
}

/** A fixed set of keys, matched by `kid`. For tests and pinned deployments. */
export function staticKeySet(keys: Jwk[]): KeySet {
  return {
    async get(kid) {
      return keys.find((key) => key.kid === kid)
    },
  }
}

export interface RemoteKeySetOptions {
  /** The JWKS endpoint, e.g. Google's `https://www.googleapis.com/oauth2/v3/certs`. */
  url: string
  /** Fetch override, for tests and custom transports. */
  fetch?: typeof globalThis.fetch
  /**
   * Cache lifetime in seconds when the response carries no `Cache-Control:
   * max-age`. Defaults to 3600.
   */
  ttl?: number
  /**
   * Minimum seconds between forced refreshes when an unknown `kid` arrives.
   * Defaults to 60. This is what lets a rotation be picked up immediately
   * without letting an attacker's made-up `kid` turn every request into a
   * fetch.
   */
  refreshCooldown?: number
}

interface JwksResponse {
  keys?: Jwk[]
}

/**
 * A `KeySet` backed by a remote JWKS, cached in memory.
 *
 * Honours `Cache-Control: max-age` and refetches once when asked for a `kid`
 * it does not hold — the signature of a rotation, not a miss. A failed refresh
 * falls back to previously fetched keys when there are any; with nothing
 * cached it throws `KeyUnavailableError`, which maps to a 500 so the provider
 * redelivers once the outage passes.
 */
export function createRemoteKeySet(options: RemoteKeySetOptions): KeySet {
  const doFetch = options.fetch ?? globalThis.fetch
  const defaultTtl = options.ttl ?? 3600
  const refreshCooldown = options.refreshCooldown ?? 60

  let keys: Map<string, Jwk> | undefined
  let expiresAt = 0
  let lastAttempt = 0
  let inflight: Promise<void> | undefined

  async function refresh(at: number): Promise<void> {
    lastAttempt = at
    let response: Response
    try {
      response = await doFetch(options.url)
    } catch (cause) {
      throw new KeyUnavailableError(`Fetching JWKS from ${options.url} failed`, { cause })
    }
    if (!response.ok) {
      throw new KeyUnavailableError(`Fetching JWKS from ${options.url} returned ${response.status}`)
    }

    let body: JwksResponse
    try {
      body = (await response.json()) as JwksResponse
    } catch (cause) {
      throw new KeyUnavailableError(`JWKS response from ${options.url} is not JSON`, { cause })
    }

    const fetched = new Map<string, Jwk>()
    for (const key of body.keys ?? []) {
      if (typeof key.kid === 'string') fetched.set(key.kid, key)
    }

    const cacheControl = response.headers.get('cache-control') ?? ''
    const maxAge = /max-age=(\d+)/.exec(cacheControl)?.[1]
    keys = fetched
    expiresAt = at + (maxAge ? Number.parseInt(maxAge, 10) : defaultTtl) * 1000
  }

  // Concurrent verifications share one request; a refresh failure surfaces to
  // the caller only when there is no previous key set to fall back on.
  async function ensureFresh(at: number): Promise<void> {
    if (keys && at < expiresAt) return
    inflight ??= refresh(at).finally(() => {
      inflight = undefined
    })
    try {
      await inflight
    } catch (error) {
      if (!keys) throw error
    }
  }

  return {
    async get(kid, now = new Date()) {
      const at = now.getTime()
      await ensureFresh(at)

      const found = keys?.get(kid)
      if (found) return found

      // An unknown kid on a fresh cache usually means the provider rotated
      // since the last fetch. Refetch once, rate-limited by the cooldown.
      if (at - lastAttempt >= refreshCooldown * 1000) {
        try {
          await refresh(at)
        } catch (error) {
          if (!keys) throw error
        }
        return keys?.get(kid)
      }
      return undefined
    },
  }
}
