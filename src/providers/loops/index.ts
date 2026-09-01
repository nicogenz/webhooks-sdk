import type { WebhookProvider } from '../../core/provider.js'
import type { EventMap } from '../../core/types.js'
import { standardWebhooks } from '../standard-webhooks/index.js'

/** A contact's identifiers. The full contact is one `Find a contact` API call away. */
export interface LoopsContactIdentity {
  id: string
  email: string
  userId: string | null
}

/** The full contact, as the `Find a contact` API returns it. */
export interface LoopsContact {
  id: string
  email: string
  firstName: string | null
  lastName: string | null
  source: string
  subscribed: boolean
  userGroup: string
  userId: string | null
  /** Ids of the mailing lists the contact is subscribed to, each mapped to `true`. */
  mailingLists: Record<string, boolean>
  /** `"accepted"` once double opt-in is confirmed; `null` when it is not in play. */
  optInStatus: string | null
  /** Custom contact properties. */
  [key: string]: unknown
}

/** One email send to one recipient. */
export interface LoopsEmail {
  id: string
  /** The sent version of the campaign, workflow, or transactional email. */
  emailMessageId: string
  subject: string
}

export interface LoopsMailingList {
  id: string
  name: string
  description: string | null
  isPublic: boolean
}

/**
 * The envelope Loops puts on the wire. Flat, not `{ type, data }`: the event
 * name is `eventName`, and the context objects sit beside it at the top level.
 */
export interface LoopsEventPayload {
  eventName: string
  /** Seconds since the epoch — when the event occurred in Loops. */
  eventTime: number
  /** `1.0.0` for every event. */
  webhookSchemaVersion: string
  [key: string]: unknown
}

/** `contact.*` events. */
export interface LoopsContactEventPayload extends LoopsEventPayload {
  contactIdentity: LoopsContactIdentity
  /** The full contact, including custom properties — `contact.created` only. */
  contact?: LoopsContact
  /** `contact.mailingList.*` only. */
  mailingList?: LoopsMailingList
}

/** `*.email.sent` and `email.*` events. */
export interface LoopsEmailEventPayload extends LoopsEventPayload {
  contactIdentity: LoopsContactIdentity
  email: LoopsEmail
  /** `email.*` events only. Workflow emails report `loop`. */
  sourceType?: 'campaign' | 'loop' | 'transactional'
  campaignId?: string
  campaignName?: string
  loopId?: string
  loopName?: string
  transactionalId?: string
  transactionalName?: string
  /** Campaign and workflow sends addressed to one or more mailing lists. */
  mailingLists?: LoopsMailingList[]
}

/** `testing.testEvent`, sent from the Webhooks settings page. */
export interface LoopsTestEventPayload extends LoopsEventPayload {
  message: string
}

// Multi-word segments are camelCase on the wire (`softBounced`, `spamReported`,
// `mailingList`) — Loops' own strings, verbatim. `loop.email.sent` keeps its
// pre-May-2026 name although the product now calls loops "workflows".
export interface LoopsEvents extends EventMap {
  'contact.created': LoopsContactEventPayload
  'contact.unsubscribed': LoopsContactEventPayload
  'contact.deleted': LoopsContactEventPayload
  'contact.mailingList.subscribed': LoopsContactEventPayload
  'contact.mailingList.unsubscribed': LoopsContactEventPayload
  'campaign.email.sent': LoopsEmailEventPayload
  'loop.email.sent': LoopsEmailEventPayload
  'transactional.email.sent': LoopsEmailEventPayload
  'email.delivered': LoopsEmailEventPayload
  'email.softBounced': LoopsEmailEventPayload
  'email.hardBounced': LoopsEmailEventPayload
  'email.opened': LoopsEmailEventPayload
  'email.clicked': LoopsEmailEventPayload
  'email.unsubscribed': LoopsEmailEventPayload
  'email.resubscribed': LoopsEmailEventPayload
  'email.spamReported': LoopsEmailEventPayload
  'testing.testEvent': LoopsTestEventPayload
}

/**
 * Loops. Standard Webhooks over the spec's `webhook-*` headers, with the
 * event name in `eventName` rather than `type` — the per-vendor deviation the
 * `eventType` option exists for.
 */
export function loops(options: {
  secret: string | string[]
  tolerance?: number
}): WebhookProvider<LoopsEvents> {
  return standardWebhooks<LoopsEvents>({
    ...options,
    id: 'loops',
    name: 'Loops',
    eventType: 'eventName',
  })
}
