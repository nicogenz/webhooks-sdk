import type { WebhookProvider } from '../../core/provider.js'
import type { EventMap } from '../../core/types.js'
import { standardWebhooks } from '../standard-webhooks/index.js'

/**
 * The webhook body is the prediction object itself, in the same shape the
 * predictions API returns it — not a thin event envelope.
 */
export interface ReplicatePredictionPayload {
  id: string
  status: string
  version?: string
  input?: Record<string, unknown>
  output?: unknown
  error?: unknown
  logs?: string | null
  metrics?: Record<string, unknown>
  created_at?: string
  started_at?: string | null
  completed_at?: string | null
  [key: string]: unknown
}

export interface ReplicateEvents extends EventMap {
  starting: ReplicatePredictionPayload
  processing: ReplicatePredictionPayload
  succeeded: ReplicatePredictionPayload
  failed: ReplicatePredictionPayload
  canceled: ReplicatePredictionPayload
  // Deadline exceeded before the prediction started running — the sixth
  // status in Replicate's prediction lifecycle.
  aborted: ReplicatePredictionPayload
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
