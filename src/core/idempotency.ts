/**
 * Deduplication across deliveries. Every major provider retries on non-2xx
 * and several deliver at-least-once even on success, so handlers see the same
 * event id more than once as a matter of course, not as an edge case.
 *
 * The interface is deliberately two methods so a Redis, KV, or Durable Object
 * store drops in without adapting anything else.
 */
export interface IdempotencyStore {
  /** Has this key been processed already? */
  seen(key: string): boolean | Promise<boolean>
  /** Record the key as processed. */
  remember(key: string, ttlMs?: number): void | Promise<void>
}

export interface MemoryIdempotencyOptions {
  /** How long a key stays remembered. Default 24h. */
  ttlMs?: number
  /** Cap on retained keys, oldest evicted first. Default 10_000. */
  maxSize?: number
  now?: () => number
}

/**
 * In-memory store, suitable for a single long-lived process and for tests.
 *
 * Not suitable for serverless or multi-instance deployments — each instance
 * keeps its own map, so a duplicate landing on a different instance is not
 * caught. Use a shared store there.
 */
export function memoryIdempotencyStore(options: MemoryIdempotencyOptions = {}): IdempotencyStore {
  const { ttlMs = 24 * 60 * 60 * 1000, maxSize = 10_000, now = Date.now } = options
  const entries = new Map<string, number>()

  const prune = (): void => {
    const current = now()
    for (const [key, expiresAt] of entries) {
      if (expiresAt <= current) entries.delete(key)
    }
    // Map preserves insertion order, so the head is the oldest entry.
    while (entries.size > maxSize) {
      const oldest = entries.keys().next()
      if (oldest.done) break
      entries.delete(oldest.value)
    }
  }

  return {
    seen(key) {
      const expiresAt = entries.get(key)
      if (expiresAt === undefined) return false
      if (expiresAt <= now()) {
        entries.delete(key)
        return false
      }
      return true
    },
    remember(key, keyTtlMs) {
      entries.set(key, now() + (keyTtlMs ?? ttlMs))
      prune()
    },
  }
}
