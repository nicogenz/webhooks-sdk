import {
  ConfigurationError,
  MissingSignatureError,
  PayloadParseError,
  SignatureVerificationError,
} from '../../core/errors.js'
import type { VerifyContext, WebhookProvider } from '../../core/provider.js'
import { assertWithinTolerance } from '../../core/scheme.js'
import type { EventMap, RawWebhook, WebhookEvent } from '../../core/types.js'
import { verifyEd25519 } from '../../crypto/ed25519.js'
import { fromHex, toHex, utf8 } from '../../crypto/encoding.js'

export const DISCORD_SIGNATURE_HEADER = 'x-signature-ed25519'
export const DISCORD_TIMESTAMP_HEADER = 'x-signature-timestamp'

/** Default replay window in seconds. */
export const DISCORD_DEFAULT_TOLERANCE = 300

/**
 * Discord signs with Ed25519 rather than a shared secret, so there is no
 * symmetric key on your side to leak — you configure the application's public
 * key and Discord holds the private one.
 */

/** Interaction types on the interactions endpoint. */
export const DISCORD_INTERACTION_TYPES: Record<number, string> = {
  1: 'ping',
  2: 'application_command',
  3: 'message_component',
  4: 'application_command_autocomplete',
  5: 'modal_submit',
}

export type DiscordMode = 'interactions' | 'events'

export interface DiscordOptions {
  /**
   * The application's public key, hex-encoded, from the Discord developer
   * portal. Pass an array to accept several during a rotation.
   */
  publicKey: string | string[]
  /**
   * Which Discord product this endpoint serves.
   *
   * `interactions` (default) is the slash-command and component endpoint,
   * where PING is type 1 and expects `{ type: 1 }` back. `events` is the
   * Webhook Events API, where PING is type 0 and expects a bare 204. The two
   * disagree on what type number means PING, so this cannot be inferred.
   */
  mode?: DiscordMode
  /**
   * Replay window in seconds. Defaults to 300; 0 disables the window.
   *
   * Discord does not document a window and its own reference library does not
   * enforce one — but the timestamp is inside the signed material precisely so
   * it can be checked, and without a window a captured interaction verifies
   * forever. Opt out only when an upstream layer deduplicates or your clocks
   * are unreliable.
   */
  tolerance?: number
}

export interface DiscordEvents extends EventMap {
  ping: unknown
  application_command: unknown
  message_component: unknown
  application_command_autocomplete: unknown
  modal_submit: unknown
}

interface DiscordInteraction {
  id?: string
  type?: number
  application_id?: string
  event?: { type?: string; timestamp?: string; data?: unknown }
}

function resolvePublicKeys(options: DiscordOptions): Uint8Array[] {
  const values = (
    Array.isArray(options.publicKey) ? options.publicKey : [options.publicKey]
  ).filter(Boolean)

  if (values.length === 0) {
    throw new ConfigurationError('No Discord public key was provided', { provider: 'discord' })
  }

  return values.map((value) => {
    const bytes = fromHex(value)
    // An Ed25519 public key is exactly 32 bytes. Catching a truncated or
    // non-hex key here beats failing every delivery with "bad signature".
    if (bytes.length !== 32) {
      throw new ConfigurationError(
        `Discord public key must be 32 bytes of hex, got ${bytes.length}`,
        { provider: 'discord' },
      )
    }
    return bytes
  })
}

/**
 * Verifies a Discord Ed25519 signature.
 *
 * The signed material is the timestamp concatenated directly with the raw
 * body — no separator, unlike most timestamped schemes.
 */
export async function verifyDiscordWebhook(
  raw: RawWebhook,
  options: DiscordOptions,
  ctx?: Partial<VerifyContext>,
): Promise<void> {
  const publicKeys = resolvePublicKeys(options)

  const signature = raw.header(DISCORD_SIGNATURE_HEADER)
  const timestamp = raw.header(DISCORD_TIMESTAMP_HEADER)

  if (!signature || !timestamp) {
    const missing = [
      !signature && DISCORD_SIGNATURE_HEADER,
      !timestamp && DISCORD_TIMESTAMP_HEADER,
    ].filter(Boolean)
    throw new MissingSignatureError(`Missing Discord header(s): ${missing.join(', ')}`, {
      provider: 'discord',
    })
  }

  const tolerance = ctx?.tolerance ?? options.tolerance ?? DISCORD_DEFAULT_TOLERANCE
  if (tolerance > 0) {
    const sentAt = Number.parseInt(timestamp, 10)
    if (Number.isNaN(sentAt)) {
      throw new MissingSignatureError(`${DISCORD_TIMESTAMP_HEADER} is not an integer`, {
        provider: 'discord',
      })
    }
    assertWithinTolerance(sentAt, { now: ctx?.now ?? new Date(), tolerance }, 'discord')
  }

  const signed = `${timestamp}${raw.text()}`
  const signatureBytes = fromHex(signature)

  for (const key of publicKeys) {
    if (await verifyEd25519(key, signatureBytes, signed)) return
  }

  throw new SignatureVerificationError('Discord signature does not match the request', {
    provider: 'discord',
  })
}

/** Turns a verified Discord request into a normalized event. */
export function parseDiscordWebhook(
  raw: RawWebhook,
  options: DiscordOptions,
): WebhookEvent<string, unknown> {
  const payload = raw.json<DiscordInteraction>()
  const timestamp = raw.header(DISCORD_TIMESTAMP_HEADER)
  const sentAt = timestamp ? Number.parseInt(timestamp, 10) : Number.NaN
  const at = Number.isNaN(sentAt) ? new Date() : new Date(sentAt * 1000)

  if ((options.mode ?? 'interactions') === 'events') {
    const event = payload.event
    if (!event?.type) {
      throw new PayloadParseError('Discord event payload has no `event.type`', {
        provider: 'discord',
      })
    }
    return {
      // The Webhook Events API sends no delivery id, so the event name and its
      // own timestamp stand in — both are stable across a redelivery, which an
      // id derived from the signature would not be.
      id: `${event.type}:${event.timestamp ?? sentAt}`,
      provider: 'discord',
      type: event.type,
      timestamp: event.timestamp ? new Date(event.timestamp) : at,
      payload,
      raw,
    }
  }

  if (typeof payload.type !== 'number') {
    throw new PayloadParseError('Discord interaction payload has no numeric `type`', {
      provider: 'discord',
    })
  }

  return {
    id: payload.id ?? `${payload.type}:${sentAt}`,
    provider: 'discord',
    type: DISCORD_INTERACTION_TYPES[payload.type] ?? `unknown_${payload.type}`,
    timestamp: at,
    payload,
    raw,
  }
}

/**
 * The Discord integration.
 *
 * Not built with `createHmacProvider`: Ed25519 is a public-key signature, not
 * an HMAC over a string. It still uses the shared replay-window primitive.
 *
 * ```ts
 * // app/api/discord/route.ts
 * export const POST = createWebhookHandler({
 *   provider: discord({ publicKey: process.env.DISCORD_PUBLIC_KEY! }),
 *   on: { application_command: async (event) => { ... } },
 * }).fetch
 * ```
 */
export function discord(options: DiscordOptions): WebhookProvider<DiscordEvents> {
  const mode = options.mode ?? 'interactions'

  return {
    id: 'discord',
    name: 'Discord',
    tolerance: options.tolerance ?? DISCORD_DEFAULT_TOLERANCE,

    // Discord probes a new endpoint with a deliberately invalid signature and
    // will not save the URL unless that probe is rejected, so the PING must be
    // verified before it is answered.
    signedHandshake: true,

    async verify(raw, ctx) {
      await verifyDiscordWebhook(raw, options, ctx)
    },

    async parse(raw) {
      return parseDiscordWebhook(raw, options)
    },

    async handshake(raw) {
      const payload = raw.json<DiscordInteraction>()

      // The two products disagree: PING is type 1 on the interactions
      // endpoint and type 0 on the Webhook Events API.
      if (mode === 'events') {
        return payload.type === 0 ? new Response(null, { status: 204 }) : undefined
      }
      return payload.type === 1 ? Response.json({ type: 1 }) : undefined
    },
  }
}

/**
 * Signs a body the way Discord would. For tests and local replay.
 *
 * Takes a private `CryptoKey` because Discord's scheme is asymmetric — there
 * is no shared secret that could produce this.
 */
export async function signDiscordWebhook(
  body: string,
  privateKey: CryptoKey,
  timestamp: number = Math.floor(Date.now() / 1000),
): Promise<Record<string, string>> {
  const signature = await crypto.subtle.sign('Ed25519', privateKey, utf8(`${timestamp}${body}`))
  return {
    [DISCORD_SIGNATURE_HEADER]: toHex(new Uint8Array(signature)),
    [DISCORD_TIMESTAMP_HEADER]: String(timestamp),
  }
}
