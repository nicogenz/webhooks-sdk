import type { WebhookProvider } from '../../core/provider.js'
import type { EventMap } from '../../core/types.js'
import { toBase64, utf8 } from '../../crypto/encoding.js'
import { standardWebhooks } from '../standard-webhooks/index.js'

/**
 * The envelope Polar puts on the wire. `data` is the full resource — a
 * checkout, order, subscription, and so on — identified by `id`.
 */
export interface PolarEventPayload {
  type: string
  /** ISO datetime of when the event occurred. */
  timestamp: string
  data: { id?: string; [key: string]: unknown }
}

export interface PolarEvents extends EventMap {
  'checkout.created': PolarEventPayload
  'checkout.updated': PolarEventPayload
  'checkout.expired': PolarEventPayload
  'customer.created': PolarEventPayload
  'customer.updated': PolarEventPayload
  'customer.deleted': PolarEventPayload
  'customer.state_changed': PolarEventPayload
  'subscription.created': PolarEventPayload
  'subscription.updated': PolarEventPayload
  'subscription.active': PolarEventPayload
  'subscription.canceled': PolarEventPayload
  'subscription.uncanceled': PolarEventPayload
  'subscription.revoked': PolarEventPayload
  'subscription.cycled': PolarEventPayload
  'subscription.past_due': PolarEventPayload
  'subscription.paused': PolarEventPayload
  'subscription.resumed': PolarEventPayload
  'order.created': PolarEventPayload
  'order.updated': PolarEventPayload
  'order.paid': PolarEventPayload
  'order.refunded': PolarEventPayload
  'refund.created': PolarEventPayload
  'refund.updated': PolarEventPayload
  'benefit.created': PolarEventPayload
  'benefit.updated': PolarEventPayload
  'benefit_grant.created': PolarEventPayload
  'benefit_grant.updated': PolarEventPayload
  'benefit_grant.revoked': PolarEventPayload
  'product.created': PolarEventPayload
  'product.updated': PolarEventPayload
  'discount.created': PolarEventPayload
  'discount.updated': PolarEventPayload
  'discount.deleted': PolarEventPayload
  'organization.updated': PolarEventPayload
}

/**
 * Polar's dashboard secret is a raw string — no `whsec_` prefix, not base64 —
 * while the Standard Webhooks scheme keys on base64-decoded bytes. Polar's own
 * SDK bridges that by base64-encoding the secret before verifying; this
 * wrapper does the same, so the secret is passed exactly as the dashboard
 * shows it.
 */
const encodeSecret = (secret: string) => toBase64(utf8(secret))

/** Polar. Standard Webhooks over the spec's `webhook-*` headers. */
export function polar(options: {
  secret: string | string[]
  tolerance?: number
}): WebhookProvider<PolarEvents> {
  const secret = Array.isArray(options.secret)
    ? options.secret.map(encodeSecret)
    : encodeSecret(options.secret)
  return standardWebhooks<PolarEvents>({ ...options, secret, id: 'polar', name: 'Polar' })
}
