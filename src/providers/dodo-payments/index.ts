import type { WebhookProvider } from '../../core/provider.js'
import type { EventMap } from '../../core/types.js'
import { standardWebhooks } from '../standard-webhooks/index.js'

/**
 * The envelope Dodo Payments puts on the wire. `data` is the affected
 * resource in its current state — a payment, subscription, refund, dispute,
 * and so on — with `payload_type` naming which kind, and the id named after
 * the resource (`payment_id`, `subscription_id`, `dispute_id`, `payout_id`).
 */
export interface DodoPaymentsEventPayload {
  business_id: string
  type: string
  /** ISO 8601 — when the event occurred, not when this delivery was sent. */
  timestamp: string
  data: {
    /**
     * `Payment`, `Subscription`, `Refund`, `Dispute`, `LicenseKey`,
     * `CreditLedgerEntry`, `CreditBalanceLow`, `AbandonedCheckout`,
     * `DunningAttempt`, `EntitlementGrant`, or `Payout`.
     */
    payload_type?: string
    payment_id?: string
    subscription_id?: string
    dispute_id?: string
    payout_id?: string
    [key: string]: unknown
  }
}

// British `cancelled` throughout, `payout.success` rather than `succeeded`,
// and `subscription.update_payment_method` in the verb form — Dodo's own wire
// strings, verbatim.
export interface DodoPaymentsEvents extends EventMap {
  'payment.succeeded': DodoPaymentsEventPayload
  'payment.failed': DodoPaymentsEventPayload
  'payment.processing': DodoPaymentsEventPayload
  'payment.cancelled': DodoPaymentsEventPayload
  'refund.succeeded': DodoPaymentsEventPayload
  'refund.failed': DodoPaymentsEventPayload
  'dispute.opened': DodoPaymentsEventPayload
  'dispute.expired': DodoPaymentsEventPayload
  'dispute.accepted': DodoPaymentsEventPayload
  'dispute.cancelled': DodoPaymentsEventPayload
  'dispute.challenged': DodoPaymentsEventPayload
  'dispute.won': DodoPaymentsEventPayload
  'dispute.lost': DodoPaymentsEventPayload
  'subscription.active': DodoPaymentsEventPayload
  'subscription.updated': DodoPaymentsEventPayload
  'subscription.on_hold': DodoPaymentsEventPayload
  'subscription.paused': DodoPaymentsEventPayload
  'subscription.unpaused': DodoPaymentsEventPayload
  'subscription.renewed': DodoPaymentsEventPayload
  'subscription.plan_changed': DodoPaymentsEventPayload
  'subscription.update_payment_method': DodoPaymentsEventPayload
  'subscription.cancelled': DodoPaymentsEventPayload
  'subscription.failed': DodoPaymentsEventPayload
  'subscription.expired': DodoPaymentsEventPayload
  'license_key.created': DodoPaymentsEventPayload
  'entitlement_grant.created': DodoPaymentsEventPayload
  'entitlement_grant.delivered': DodoPaymentsEventPayload
  'entitlement_grant.failed': DodoPaymentsEventPayload
  'entitlement_grant.revoked': DodoPaymentsEventPayload
  'credit.added': DodoPaymentsEventPayload
  'credit.deducted': DodoPaymentsEventPayload
  'credit.expired': DodoPaymentsEventPayload
  'credit.rolled_over': DodoPaymentsEventPayload
  'credit.rollover_forfeited': DodoPaymentsEventPayload
  'credit.overage_charged': DodoPaymentsEventPayload
  'credit.overage_reset': DodoPaymentsEventPayload
  'credit.manual_adjustment': DodoPaymentsEventPayload
  'credit.balance_low': DodoPaymentsEventPayload
  'abandoned_checkout.detected': DodoPaymentsEventPayload
  'abandoned_checkout.recovered': DodoPaymentsEventPayload
  'dunning.started': DodoPaymentsEventPayload
  'dunning.recovered': DodoPaymentsEventPayload
  // Previously emitted as `payout.not_initiated`; that name is retired.
  'payout.created': DodoPaymentsEventPayload
  'payout.in_progress': DodoPaymentsEventPayload
  'payout.on_hold': DodoPaymentsEventPayload
  'payout.success': DodoPaymentsEventPayload
  'payout.failed': DodoPaymentsEventPayload
}

/** Dodo Payments. Standard Webhooks over the spec's `webhook-*` headers. */
export function dodoPayments(options: {
  secret: string | string[]
  tolerance?: number
}): WebhookProvider<DodoPaymentsEvents> {
  return standardWebhooks<DodoPaymentsEvents>({
    ...options,
    id: 'dodo-payments',
    name: 'Dodo Payments',
  })
}
