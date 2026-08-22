import type { WebhookProvider } from '../../core/provider.js'
import type { EventMap } from '../../core/types.js'
import { standardWebhooks } from '../standard-webhooks/index.js'

export interface ReplicateEvents extends EventMap {
  starting: unknown
  processing: unknown
  succeeded: unknown
  failed: unknown
  canceled: unknown
}

/**
 * Replicate. Standard Webhooks, but the event name is the prediction `status`
 * rather than a `type` field — which is exactly the kind of per-vendor
 * deviation the `eventType` option exists for.
 */
export function replicate(options: {
  secret: string | string[]
  tolerance?: number
}): WebhookProvider<ReplicateEvents> {
  return standardWebhooks<ReplicateEvents>({
    ...options,
    id: 'replicate',
    name: 'Replicate',
    eventType: 'status',
  })
}
