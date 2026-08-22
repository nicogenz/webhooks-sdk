import { MissingSignatureError, PayloadParseError } from '../../core/errors.js'
import type { WebhookProvider } from '../../core/provider.js'
import type { HmacProviderConfig, SignatureMaterial } from '../../core/scheme.js'
import { createHmacProvider, verifyWithScheme } from '../../core/scheme.js'
import type { EventMap, RawWebhook, WebhookEvent } from '../../core/types.js'
import { digestHex } from '../../crypto/hash.js'
import { hmacHex } from '../../crypto/hmac.js'

export const GITHUB_SIGNATURE_HEADER = 'x-hub-signature-256'
export const GITHUB_EVENT_HEADER = 'x-github-event'
export const GITHUB_DELIVERY_HEADER = 'x-github-delivery'

export interface GitHubOptions {
  /** The webhook secret configured on the repository, org, or app. */
  secret: string | string[]
}

/**
 * Common GitHub event names, for autocomplete. The event name arrives in the
 * `X-GitHub-Event` header rather than the body.
 */
export interface GitHubEvents extends EventMap {
  push: unknown
  ping: unknown
  pull_request: unknown
  pull_request_review: unknown
  pull_request_review_comment: unknown
  issues: unknown
  issue_comment: unknown
  release: unknown
  create: unknown
  delete: unknown
  fork: unknown
  star: unknown
  watch: unknown
  workflow_run: unknown
  workflow_job: unknown
  check_run: unknown
  check_suite: unknown
  deployment: unknown
  deployment_status: unknown
  installation: unknown
  installation_repositories: unknown
  repository: unknown
  member: unknown
  team: unknown
}

function extract(raw: RawWebhook): SignatureMaterial {
  const header = raw.header(GITHUB_SIGNATURE_HEADER)
  if (!header) {
    throw new MissingSignatureError(`Missing ${GITHUB_SIGNATURE_HEADER} header`, {
      provider: 'github',
    })
  }

  // The legacy X-Hub-Signature (SHA-1) header is deliberately not accepted.
  const [scheme, provided] = header.split('=', 2)
  if (scheme !== 'sha256' || !provided) {
    throw new MissingSignatureError(
      `Expected a "sha256=" signature, received "${header.slice(0, 16)}"`,
      { provider: 'github' },
    )
  }

  return { candidates: [provided] }
}

/** Turns a verified GitHub request into a normalized event. */
export async function parseGitHubWebhook(raw: RawWebhook): Promise<WebhookEvent<string, unknown>> {
  const type = raw.header(GITHUB_EVENT_HEADER)
  if (!type) {
    throw new PayloadParseError(`Missing ${GITHUB_EVENT_HEADER} header`, { provider: 'github' })
  }

  // GitHub documents this header as present on every delivery, so its absence
  // marks a malformed request. It is deliberately NOT the event id: the
  // signature covers only the body, so a replayed body could carry any fresh
  // GUID and mint a new idempotency key at will.
  const delivery = raw.header(GITHUB_DELIVERY_HEADER)
  if (!delivery) {
    throw new PayloadParseError(`Missing ${GITHUB_DELIVERY_HEADER} header`, { provider: 'github' })
  }

  const payload = raw.json<Record<string, unknown>>()

  // GitHub carries no event timestamp in a consistent place, so receipt time
  // is the honest answer rather than digging a per-event field out of the body.
  return {
    // A digest of the signed body is the one thing a replay cannot vary, so
    // it — not the unsigned delivery GUID — is what the idempotency store
    // keys on. The GUID stays readable via raw.header('x-github-delivery').
    id: await digestHex('SHA-256', raw.text()),
    provider: 'github',
    type,
    timestamp: new Date(),
    payload,
    raw,
  }
}

/**
 * GitHub signs the raw body with HMAC-SHA256 and sends it hex-encoded as
 * `sha256=...`. No timestamp is signed, so the scheme offers no replay
 * protection on its own — pair it with an idempotency store, which keys on a
 * digest of the signed body because `X-GitHub-Delivery` is outside the
 * signature and a replay could mint a fresh GUID.
 */
function schemeFor(options: GitHubOptions): HmacProviderConfig {
  return {
    id: 'github',
    name: 'GitHub',
    secret: options.secret,
    encoding: 'hex',
    extract,
    content: (_material, raw) => raw.text(),
    event: parseGitHubWebhook,
  }
}

/** Verifies a GitHub webhook signature. */
export async function verifyGitHubWebhook(raw: RawWebhook, options: GitHubOptions): Promise<void> {
  await verifyWithScheme(raw, schemeFor(options))
}

/** The GitHub integration. Covers repository, organization, and App webhooks. */
export function github(options: GitHubOptions): WebhookProvider<GitHubEvents> {
  return createHmacProvider<GitHubEvents>(schemeFor(options))
}

/** Produces a valid `X-Hub-Signature-256` value. For tests and local replay. */
export async function signGitHubWebhook(body: string, secret: string): Promise<string> {
  return `sha256=${await hmacHex('SHA-256', secret, body)}`
}
