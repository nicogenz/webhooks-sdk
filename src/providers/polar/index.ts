import type { WebhookProvider } from '../../core/provider.js'
import type { EventMap } from '../../core/types.js'
import { standardWebhooks } from '../standard-webhooks/index.js'

export interface PolarEvents extends EventMap {
  'checkout.created': unknown
  'checkout.updated': unknown
  'order.created': unknown
  'order.paid': unknown
  'order.refunded': unknown
  'subscription.created': unknown
  'subscription.updated': unknown
  'subscription.active': unknown
  'subscription.canceled': unknown
  'subscription.uncanceled': unknown
  'subscription.revoked': unknown
  'customer.created': unknown
  'customer.updated': unknown
  'customer.deleted': unknown
  'benefit_grant.created': unknown
  'benefit_grant.revoked': unknown
}

/** Polar. Standard Webhooks over the spec's `webhook-*` headers. */
export function polar(options: {
  secret: string | string[]
  tolerance?: number
}): WebhookProvider<PolarEvents> {
  return standardWebhooks<PolarEvents>({ ...options, id: 'polar', name: 'Polar' })
}
