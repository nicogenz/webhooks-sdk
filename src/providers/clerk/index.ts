import type { WebhookProvider } from '../../core/provider.js'
import type { EventMap } from '../../core/types.js'
import { standardWebhooks } from '../standard-webhooks/index.js'

/**
 * The envelope Clerk puts on the wire. `data` is the affected resource — a
 * user, session, organization, and so on — identified by `id`.
 */
export interface ClerkEventPayload {
  data: { id?: string; [key: string]: unknown }
  object?: 'event'
  type: string
  /** Milliseconds — unlike the signed svix-timestamp header, which is seconds. */
  timestamp?: number
  instance_id?: string
}

// Multi-word resources are camelCase on the wire (`organizationMembership`,
// `waitlistEntry`, `subscription.pastDue`) — Clerk's own strings, verbatim.
export interface ClerkEvents extends EventMap {
  'user.created': ClerkEventPayload
  'user.updated': ClerkEventPayload
  'user.deleted': ClerkEventPayload
  'session.created': ClerkEventPayload
  'session.ended': ClerkEventPayload
  'session.removed': ClerkEventPayload
  'session.revoked': ClerkEventPayload
  'email.created': ClerkEventPayload
  'sms.created': ClerkEventPayload
  'organization.created': ClerkEventPayload
  'organization.updated': ClerkEventPayload
  'organization.deleted': ClerkEventPayload
  'organizationDomain.created': ClerkEventPayload
  'organizationDomain.updated': ClerkEventPayload
  'organizationDomain.deleted': ClerkEventPayload
  'organizationInvitation.created': ClerkEventPayload
  'organizationInvitation.accepted': ClerkEventPayload
  'organizationInvitation.revoked': ClerkEventPayload
  'organizationMembership.created': ClerkEventPayload
  'organizationMembership.updated': ClerkEventPayload
  'organizationMembership.deleted': ClerkEventPayload
  'role.created': ClerkEventPayload
  'role.updated': ClerkEventPayload
  'role.deleted': ClerkEventPayload
  'permission.created': ClerkEventPayload
  'permission.updated': ClerkEventPayload
  'permission.deleted': ClerkEventPayload
  'waitlistEntry.created': ClerkEventPayload
  'waitlistEntry.updated': ClerkEventPayload
  'paymentAttempt.created': ClerkEventPayload
  'paymentAttempt.updated': ClerkEventPayload
  'subscription.created': ClerkEventPayload
  'subscription.updated': ClerkEventPayload
  'subscription.active': ClerkEventPayload
  'subscription.pastDue': ClerkEventPayload
  'subscriptionItem.created': ClerkEventPayload
  'subscriptionItem.updated': ClerkEventPayload
  'subscriptionItem.active': ClerkEventPayload
  'subscriptionItem.canceled': ClerkEventPayload
  'subscriptionItem.upcoming': ClerkEventPayload
  'subscriptionItem.ended': ClerkEventPayload
  'subscriptionItem.abandoned': ClerkEventPayload
  'subscriptionItem.incomplete': ClerkEventPayload
  'subscriptionItem.pastDue': ClerkEventPayload
  'subscriptionItem.freeTrialEnding': ClerkEventPayload
}

/** Clerk. Standard Webhooks over the legacy `svix-*` headers. */
export function clerk(options: {
  secret: string | string[]
  tolerance?: number
}): WebhookProvider<ClerkEvents> {
  return standardWebhooks<ClerkEvents>({ ...options, id: 'clerk', name: 'Clerk' })
}
