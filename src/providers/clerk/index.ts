import type { WebhookProvider } from '../../core/provider.js'
import type { EventMap } from '../../core/types.js'
import { standardWebhooks } from '../standard-webhooks/index.js'

export interface ClerkEvents extends EventMap {
  'user.created': unknown
  'user.updated': unknown
  'user.deleted': unknown
  'session.created': unknown
  'session.ended': unknown
  'session.removed': unknown
  'session.revoked': unknown
  'organization.created': unknown
  'organization.updated': unknown
  'organization.deleted': unknown
  'organizationMembership.created': unknown
  'organizationMembership.updated': unknown
  'organizationMembership.deleted': unknown
  'organizationInvitation.created': unknown
  'email.created': unknown
}

/** Clerk. Standard Webhooks over the legacy `svix-*` headers. */
export function clerk(options: {
  secret: string | string[]
  tolerance?: number
}): WebhookProvider<ClerkEvents> {
  return standardWebhooks<ClerkEvents>({ ...options, id: 'clerk', name: 'Clerk' })
}
