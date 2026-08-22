export type WebhookErrorCode =
  | 'missing_signature'
  | 'invalid_signature'
  | 'timestamp_out_of_tolerance'
  | 'invalid_payload'
  | 'invalid_configuration'
  | 'key_unavailable'
  | 'duplicate_event'
  | 'unknown_provider'
  | 'handler_failed'

const DEFAULT_STATUS: Record<WebhookErrorCode, number> = {
  missing_signature: 400,
  invalid_signature: 401,
  timestamp_out_of_tolerance: 400,
  invalid_payload: 400,
  invalid_configuration: 500,
  // 5xx so the provider retries — the request may well be genuine, we just
  // could not reach the key material needed to decide.
  key_unavailable: 500,
  // A duplicate is not a failure from the sender's point of view: acknowledge
  // it so the provider stops redelivering.
  duplicate_event: 200,
  unknown_provider: 404,
  // 5xx so the provider retries — the delivery was valid, we failed to act.
  handler_failed: 500,
}

export interface WebhookErrorOptions {
  provider?: string
  status?: number
  cause?: unknown
}

export class WebhookError extends Error {
  readonly code: WebhookErrorCode
  readonly status: number
  readonly provider: string | undefined

  constructor(code: WebhookErrorCode, message: string, options: WebhookErrorOptions = {}) {
    super(message, { cause: options.cause })
    this.name = new.target.name
    this.code = code
    this.status = options.status ?? DEFAULT_STATUS[code]
    this.provider = options.provider
  }

  /** True for any error that means "do not trust this request". */
  get isVerificationFailure(): boolean {
    return (
      this.code === 'missing_signature' ||
      this.code === 'invalid_signature' ||
      this.code === 'timestamp_out_of_tolerance'
    )
  }

  toJSON() {
    return { error: this.code, message: this.message, provider: this.provider }
  }
}

/** The request carried no signature header at all. */
export class MissingSignatureError extends WebhookError {
  constructor(message: string, options?: WebhookErrorOptions) {
    super('missing_signature', message, options)
  }
}

/** A signature was present but did not match the computed one. */
export class SignatureVerificationError extends WebhookError {
  constructor(message: string, options?: WebhookErrorOptions) {
    super('invalid_signature', message, options)
  }
}

/** The signed timestamp fell outside the replay window. */
export class TimestampToleranceError extends WebhookError {
  constructor(message: string, options?: WebhookErrorOptions) {
    super('timestamp_out_of_tolerance', message, options)
  }
}

/** The body verified but could not be read as a valid event. */
export class PayloadParseError extends WebhookError {
  constructor(message: string, options?: WebhookErrorOptions) {
    super('invalid_payload', message, options)
  }
}

/** The SDK was set up wrong — a missing secret, a malformed key. */
export class ConfigurationError extends WebhookError {
  constructor(message: string, options?: WebhookErrorOptions) {
    super('invalid_configuration', message, options)
  }
}

/**
 * Remote key material (a JWKS, a signing certificate) could not be fetched, so
 * the request could not be judged either way. Deliberately not a verification
 * failure — treating "our key fetch failed" as "their signature is bad" would
 * report an outage as an attack.
 */
export class KeyUnavailableError extends WebhookError {
  constructor(message: string, options?: WebhookErrorOptions) {
    super('key_unavailable', message, options)
  }
}

/** This event id has already been processed. */
export class DuplicateEventError extends WebhookError {
  constructor(message: string, options?: WebhookErrorOptions) {
    super('duplicate_event', message, options)
  }
}

/** The router could not resolve a provider for the request. */
export class UnknownProviderError extends WebhookError {
  constructor(message: string, options?: WebhookErrorOptions) {
    super('unknown_provider', message, options)
  }
}

/** A user handler threw. The delivery was genuine; our side failed. */
export class HandlerError extends WebhookError {
  constructor(message: string, options?: WebhookErrorOptions) {
    super('handler_failed', message, options)
  }
}

export function isWebhookError(value: unknown): value is WebhookError {
  return value instanceof WebhookError
}
