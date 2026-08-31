import type { WebhookProvider } from '../../core/provider.js'
import type { EventMap } from '../../core/types.js'
import { standardWebhooks } from '../standard-webhooks/index.js'

/**
 * The envelope OpenAI puts on the wire. `data` is thin by design — usually
 * just the id of the resource the event refers to; fetch the full object
 * through the API.
 */
export interface OpenAIEventPayload {
  id: string
  object?: 'event'
  type: string
  created_at: number
  data: { id?: string; [key: string]: unknown }
}

export interface OpenAIEvents extends EventMap {
  'response.completed': OpenAIEventPayload
  'response.cancelled': OpenAIEventPayload
  'response.failed': OpenAIEventPayload
  'response.incomplete': OpenAIEventPayload
  'batch.completed': OpenAIEventPayload
  'batch.cancelled': OpenAIEventPayload
  'batch.expired': OpenAIEventPayload
  'batch.failed': OpenAIEventPayload
  'fine_tuning.job.succeeded': OpenAIEventPayload
  'fine_tuning.job.failed': OpenAIEventPayload
  'fine_tuning.job.cancelled': OpenAIEventPayload
  'eval.run.succeeded': OpenAIEventPayload
  'eval.run.failed': OpenAIEventPayload
  // Single `l` on this one, double elsewhere — OpenAI's wire strings, verbatim.
  'eval.run.canceled': OpenAIEventPayload
  'realtime.call.incoming': OpenAIEventPayload
  'live.call.incoming': OpenAIEventPayload
  'safety.alert.created': OpenAIEventPayload
}

/** OpenAI. Standard Webhooks over the spec's `webhook-*` headers. */
export function openai(options: {
  secret: string | string[]
  tolerance?: number
}): WebhookProvider<OpenAIEvents> {
  return standardWebhooks<OpenAIEvents>({ ...options, id: 'openai', name: 'OpenAI' })
}
