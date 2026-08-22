import type { WebhookProvider } from '../../core/provider.js'
import type { EventMap } from '../../core/types.js'
import { standardWebhooks } from '../standard-webhooks/index.js'

export interface ResendEvents extends EventMap {
  'email.sent': unknown
  'email.delivered': unknown
  'email.delivery_delayed': unknown
  'email.bounced': unknown
  'email.complained': unknown
  'email.opened': unknown
  'email.clicked': unknown
  'contact.created': unknown
  'contact.updated': unknown
  'contact.deleted': unknown
  'domain.created': unknown
  'domain.updated': unknown
  'domain.deleted': unknown
}

/** Resend. Standard Webhooks over the legacy `svix-*` headers. */
export function resend(options: {
  secret: string | string[]
  tolerance?: number
}): WebhookProvider<ResendEvents> {
  return standardWebhooks<ResendEvents>({ ...options, id: 'resend', name: 'Resend' })
}
