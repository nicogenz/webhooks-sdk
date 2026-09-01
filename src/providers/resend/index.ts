import type { WebhookProvider } from '../../core/provider.js'
import type { EventMap } from '../../core/types.js'
import { standardWebhooks } from '../standard-webhooks/index.js'

/**
 * The envelope Resend puts on the wire. `data` is event-specific — email
 * events name the send in `email_id`; contact, domain, and suppression
 * events name the resource in `id`.
 */
export interface ResendEventPayload {
  type: string
  created_at: string
  data: { email_id?: string; id?: string; [key: string]: unknown }
}

export interface ResendEvents extends EventMap {
  'email.sent': ResendEventPayload
  'email.scheduled': ResendEventPayload
  'email.delivered': ResendEventPayload
  'email.delivery_delayed': ResendEventPayload
  'email.bounced': ResendEventPayload
  'email.complained': ResendEventPayload
  'email.failed': ResendEventPayload
  'email.opened': ResendEventPayload
  'email.clicked': ResendEventPayload
  'email.received': ResendEventPayload
  'email.suppressed': ResendEventPayload
  'contact.created': ResendEventPayload
  'contact.updated': ResendEventPayload
  'contact.deleted': ResendEventPayload
  'domain.created': ResendEventPayload
  'domain.updated': ResendEventPayload
  'domain.deleted': ResendEventPayload
  'suppression.added': ResendEventPayload
  'suppression.removed': ResendEventPayload
}

/** Resend. Standard Webhooks over the legacy `svix-*` headers. */
export function resend(options: {
  secret: string | string[]
  tolerance?: number
}): WebhookProvider<ResendEvents> {
  return standardWebhooks<ResendEvents>({ ...options, id: 'resend', name: 'Resend' })
}
