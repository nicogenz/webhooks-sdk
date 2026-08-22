# Integrations

Every webhook provider claims a bespoke signature scheme. Most of them are not
bespoke at all — roughly nine families cover almost everything on this page.
Implementing a family is the expensive part; each additional provider inside a
family is then a header name, an encoding, and a test fixture.

That is the organizing idea behind this catalog: it is a map of families first
and a checklist of vendors second.

**Status:** ✅ shipped · ✅ ᵍ works today via the generic `standard-webhooks`
provider, no named wrapper yet · 🚧 in progress · 📋 planned · 🔍 needs research

> Rows marked 🔍 are ones where the scheme is known to vary by product tier or
> API version and must be re-read against current provider docs before being
> implemented. Every row is verified against live documentation at
> implementation time, not at listing time.

---

## Scheme families

| # | Family | How it works | Replay-safe on its own | Examples |
|---|--------|--------------|------------------------|----------|
| 1 | **HMAC over raw body** | `HMAC(secret, rawBody)`, hex or base64, in one header | ❌ — pair with an idempotency store | GitHub, Shopify, Lemon Squeezy, Sentry |
| 2 | **HMAC over timestamp + body** | `HMAC(secret, "{ts}.{body}")`, timestamp sent alongside | ✅ | Stripe, Paddle, Slack, WorkOS |
| 3 | **Standard Webhooks / Svix** | `HMAC(base64(secret), "{id}.{ts}.{body}")`, versioned `v1,…` list | ✅ | Resend, Clerk, Polar, OpenAI |
| 4 | **Ed25519** | Public-key signature over `ts + body`; no shared secret to leak | ✅ | Discord |
| 5 | **JWT / JWKS** | Signed token in a header, verified against a rotating public key set | ✅ (via `exp`) | Google Pub/Sub, Plaid, Wix |
| 6 | **X.509 cert chain** | RSA signature; fetch and validate the signing cert from the provider | ✅ | PayPal, AWS SNS |
| 7 | **Canonical string HMAC** | Signs a reconstructed string (URL + sorted params), not the raw body | ⚠️ varies | Twilio, Square, Adyen, Trello |
| 8 | **Shared token compare** | A static secret echoed in a header; constant-time compare only | ❌ | GitLab, Telegram, Google Drive |
| 9 | **None / out-of-band** | No signature — re-fetch the resource by id, or use mTLS/basic auth/IP allowlist | ❌ | Mollie, Postmark, Docker Hub |

Families 1–4 are pure Web Crypto and ship in the zero-dependency core.
Families 5 and 6 need a fetch of remote key material, so they carry a pluggable
cache. Family 7 is the awkward one: the signature covers a string the SDK has
to rebuild, which means the adapter must know the public URL of your endpoint —
proxies and rewrites break it, and that has to be configurable.

### Discord ships two products that disagree

Discord has an interactions endpoint and a Webhook Events API. Both use the
same Ed25519 verification, and both open with a PING — but PING is `type: 1`
on one and `type: 0` on the other, and they want different answers (`{type:1}`
versus a bare 204). Since `type: 1` means "an event" in the second product,
nothing in the payload distinguishes them, so this SDK takes a `mode` option
rather than guessing.

### Family 3 is one implementation, not nine

Standard Webhooks is specified tightly enough that every vendor on it is the
same code. `webhooks-sdk/standard-webhooks` implements the spec — symmetric
`v1` and asymmetric `v1a`, both header generations — and a named provider is
then a slug plus an event-name field:

```ts
export function resend(options: { secret: string | string[] }) {
  return standardWebhooks<ResendEvents>({ ...options, id: 'resend', name: 'Resend' })
}
```

Vendors marked ✅ ᵍ above already work without a wrapper:

```ts
standardWebhooks({ id: 'openai', secret: process.env.OPENAI_WEBHOOK_SECRET! })
```

Two details the spec makes easy to get wrong. The secret is base64 **after**
the `whsec_` prefix, so signing the literal string produces a digest that never
matches — this SDK fails loudly at config time instead. And the signature header
holds a space-delimited list of versioned candidates, so a single-signature
implementation breaks during key rotation.

### Why family 1 needs help

An HMAC over the body alone proves *who* sent the request but not *when*. The
same bytes replayed a week later verify perfectly. For those providers the SDK
leans on an [idempotency store](./README.md#idempotency) keyed on a digest of
the signed body — not on the delivery id, which lives in an unsigned header a
replay could mint fresh — and that same store protects you from the ordinary
at-least-once redelivery that every provider on this page does.

---

## Payments & billing

| Provider | Scheme | Key headers | Event name from | Status |
|----------|--------|-------------|-----------------|--------|
| Stripe | 2 · HMAC `t=`/`v1=`, SHA-256 hex | `Stripe-Signature` | body `.type` | ✅ |
| Paddle (Billing) | 2 · HMAC `ts=`/`h1=`, SHA-256 hex | `Paddle-Signature` | body `.event_type` | 📋 |
| Lemon Squeezy | 1 · HMAC SHA-256 hex | `X-Signature` | `X-Event-Name` | 📋 |
| Polar | 3 · Standard Webhooks | `webhook-id`, `webhook-timestamp`, `webhook-signature` | body `.type` | ✅ |
| Dodo Payments | 3 · Standard Webhooks | `webhook-*` | body `.type` | ✅ ᵍ |
| Square | 7 · HMAC SHA-256 base64 over `notificationURL + body` | `x-square-hmacsha256-signature` | body `.type` | 📋 |
| PayPal | 6 · RSA-SHA256 + cert chain | `PAYPAL-TRANSMISSION-SIG`, `PAYPAL-CERT-URL`, `PAYPAL-TRANSMISSION-ID/-TIME`, `PAYPAL-AUTH-ALGO` | body `.event_type` | 📋 |
| Adyen | 7 · HMAC SHA-256 base64 over escaped field concat | body `additionalData.hmacSignature` | body `eventCode` | 🔍 |
| Braintree | 9 · signed payload pair, verified via SDK | form `bt_signature`, `bt_payload` | parsed notification | 🔍 |
| Chargebee | 9 · HTTP basic auth | `Authorization` | body `.event_type` | 📋 |
| Recurly | 9 · basic auth / IP allowlist | `Authorization` | XML root element | 🔍 |
| Mollie | 9 · none — re-fetch payment by id | — | n/a (id only) | 📋 |
| Razorpay | 1 · HMAC SHA-256 hex | `X-Razorpay-Signature` | body `.event` | 📋 |
| Coinbase Commerce | 1 · HMAC SHA-256 hex | `X-CC-Webhook-Signature` | body `.event.type` | 📋 |
| GoCardless | 1 · HMAC SHA-256 hex | `Webhook-Signature` | per-event `.action` | 📋 |
| Plaid | 5 · JWT ES256, JWKS via API | `Plaid-Verification` | body `.webhook_code` | 📋 |
| Stripe Issuing / Connect | 2 · same as Stripe, different secret per endpoint | `Stripe-Signature` | body `.type` | ✅ |

**Notes.** Mollie deliberately sends only an id and expects you to call the API
back — treating that as a verification failure is a common mistake. Adyen's
signature covers a field concatenation with its own escaping rules rather than
the raw body, so it cannot reuse family 1.

---

## Developer platforms & CI

| Provider | Scheme | Key headers | Event name from | Status |
|----------|--------|-------------|-----------------|--------|
| GitHub | 1 · HMAC SHA-256 hex, `sha256=` | `X-Hub-Signature-256`, `X-GitHub-Delivery` | `X-GitHub-Event` | ✅ |
| GitLab | 8 · shared token | `X-Gitlab-Token` | `X-Gitlab-Event` | 📋 |
| Bitbucket | 1 · HMAC SHA-256 hex, `sha256=` | `X-Hub-Signature` | `X-Event-Key` | 📋 |
| Gitea / Forgejo | 1 · HMAC SHA-256 hex | `X-Gitea-Signature` | `X-Gitea-Event` | 📋 |
| Linear | 1 · HMAC SHA-256 hex | `Linear-Signature` | `Linear-Event` | 📋 |
| Vercel | 1 · HMAC SHA-1 hex | `x-vercel-signature` | body `.type` | 🔍 |
| Netlify | 5 · JWS (HS256) | `X-Webhook-Signature` | body `.state` | 🔍 |
| Cloudflare | varies by product | varies | varies | 🔍 |
| CircleCI | 2 · HMAC SHA-256 hex, `v1=` | `circleci-signature` | body `.type` | 📋 |
| Sentry | 1 · HMAC SHA-256 hex | `Sentry-Hook-Signature` | `Sentry-Hook-Resource` | 📋 |
| Jira / Atlassian | 5 · JWT (Connect apps) | `Authorization` | body `.webhookEvent` | 🔍 |
| Docker Hub | 9 · none | — | body | 📋 |
| Sonatype / Nexus | 1 · HMAC SHA-1 hex | `X-Nexus-Webhook-Signature` | `X-Nexus-Webhook-Id` | 🔍 |

---

## Google

Google is not one webhook system. It is five, and most of them funnel through
Pub/Sub rather than posting to you directly — which is why "does it support
Google" has no single answer.

| Surface | Delivery | Scheme | Status |
|---------|----------|--------|--------|
| Cloud Pub/Sub **push** | Direct POST, base64 message in `.message.data` | 5 · OIDC JWT in `Authorization: Bearer`, verified against Google's JWKS with an audience and service-account email check | ✅ |
| Gmail API push | Via Pub/Sub | 5 · inherits Pub/Sub | ✅ via `google-pubsub` |
| Google Calendar push | Direct POST, **no body** | 8 · `X-Goog-Channel-Token`; state in `X-Goog-Resource-State`, `X-Goog-Channel-ID`, `X-Goog-Message-Number` | 📋 |
| Google Drive push | Direct POST, no body | 8 · same channel-token model as Calendar | 📋 |
| Google Workspace Events API | Via Pub/Sub | 5 · inherits Pub/Sub | ✅ via `google-pubsub` |
| Google Play RTDN | Via Pub/Sub | 5 · inherits Pub/Sub | ✅ via `google-pubsub` |
| Google Chat apps | Direct POST | 5 · bearer JWT audience check | 🔍 |

**The awkward part.** Calendar and Drive notifications carry no payload at all
— just headers saying "something on this channel changed", after which you call
the API to find out what. The normalized envelope still works, but `payload` is
empty and `type` comes from `X-Goog-Resource-State`. Channels also expire and
must be renewed, which is subscription management rather than webhook handling
and stays out of scope.

Pub/Sub push additionally requires that you unwrap the base64 envelope before
the inner event is visible. The `google-pubsub` provider does that unwrapping —
`event.payload.message` carries the decoded bytes with `text()` and `json()`
accessors, so a Gmail or Play event reaches your handler as an event, not as
an envelope.

---

## Communication & messaging

| Provider | Scheme | Key headers | Event name from | Status |
|----------|--------|-------------|-----------------|--------|
| Slack | 2 · HMAC SHA-256 hex over `v0:{ts}:{body}` | `X-Slack-Signature`, `X-Slack-Request-Timestamp` | body `.event.type` | 📋 |
| Discord | 4 · Ed25519 over `ts + body` | `X-Signature-Ed25519`, `X-Signature-Timestamp` | body `.type` | ✅ |
| Telegram | 8 · shared token | `X-Telegram-Bot-Api-Secret-Token` | update key | 📋 |
| Twilio | 7 · HMAC SHA-1 base64 over URL + sorted params | `X-Twilio-Signature` | form fields | ✅ |
| Meta / WhatsApp / Instagram | 1 · HMAC SHA-256 hex, `sha256=` | `X-Hub-Signature-256` | body `.entry[].changes[].field` | 📋 |
| SendGrid | 5 · ECDSA over `ts + body` | `X-Twilio-Email-Event-Webhook-Signature/-Timestamp` | per-item `.event` | 📋 |
| Mailgun | 1 · HMAC SHA-256 hex over `ts + token` | body `signature{}` | body `event-data.event` | 📋 |
| Postmark | 9 · basic auth / IP allowlist | `Authorization` | body `.RecordType` | 📋 |
| Resend | 3 · Standard Webhooks | `svix-id`, `svix-timestamp`, `svix-signature` | body `.type` | ✅ |
| Loops | 3 · Standard Webhooks | `svix-*` | body `.type` | ✅ ᵍ |
| Intercom | 1 · HMAC SHA-1 hex, `sha1=` | `X-Hub-Signature` | body `.topic` | 📋 |
| Zendesk | 2 · HMAC SHA-256 base64 over `ts + body` | `X-Zendesk-Webhook-Signature/-Timestamp` | body `.type` | 📋 |
| Front | 1 · HMAC SHA-256 base64 | `X-Front-Signature` | body `.type` | 🔍 |
| Pusher | 1 · HMAC SHA-256 hex | `X-Pusher-Signature`, `X-Pusher-Key` | per-event `.name` | 📋 |
| Zoom | 2 · HMAC SHA-256 hex over `v0:{ts}:{body}` | `x-zm-signature`, `x-zm-request-timestamp` | body `.event` | 📋 |
| Twitch EventSub | 2 · HMAC SHA-256 hex over `id + ts + body` | `Twitch-Eventsub-Message-Signature/-Id/-Timestamp/-Type` | `Twitch-Eventsub-Subscription-Type` | 📋 |

---

## Auth & identity

| Provider | Scheme | Key headers | Event name from | Status |
|----------|--------|-------------|-----------------|--------|
| Clerk | 3 · Standard Webhooks | `svix-id`, `svix-timestamp`, `svix-signature` | body `.type` | ✅ |
| WorkOS | 2 · HMAC `t=`/`v1=`, SHA-256 hex | `WorkOS-Signature` | body `.event` | 📋 |
| Auth0 (Log Streams) | 9 · custom auth header | user-defined | body `.data.type` | 🔍 |
| Okta (Event Hooks) | 8 · shared secret header, one-time GET verification | `Authorization`, `X-Okta-Verification-Challenge` | body `.eventType` | 📋 |
| Stytch | 3 · Standard Webhooks | `svix-*` | body `.action` | ✅ ᵍ |
| Kinde | 5 · JWT RS256, JWKS | body is the JWT | JWT `.type` | 🔍 |
| Supabase | 9 · user-defined headers on DB webhooks | user-defined | body `.type` | 📋 |
| Firebase | n/a · Cloud Functions triggers, not HTTP webhooks | — | — | — |

---

## Commerce

| Provider | Scheme | Key headers | Event name from | Status |
|----------|--------|-------------|-----------------|--------|
| Shopify | 1 · HMAC SHA-256 base64 | `X-Shopify-Hmac-SHA256` | `X-Shopify-Topic` | 📋 |
| WooCommerce | 1 · HMAC SHA-256 base64 | `X-WC-Webhook-Signature` | `X-WC-Webhook-Topic` | 📋 |
| BigCommerce | 9 · none by default; custom headers | user-defined | body `.scope` | 📋 |
| Wix | 5 · JWT RS256 | body is the JWT | decoded `.eventType` | 🔍 |
| Squarespace | 1 · HMAC SHA-256 base64 | `Squarespace-Signature` | body `.topic` | 🔍 |
| Amazon SP-API | 6 · via SNS/EventBridge | SNS headers | notification type | 🔍 |

---

## Productivity & CRM

| Provider | Scheme | Key headers | Event name from | Status |
|----------|--------|-------------|-----------------|--------|
| Notion | 1 · HMAC SHA-256 hex, `sha256=`; one-time verification token on subscribe | `X-Notion-Signature` | body `.type` | 📋 |
| Airtable | 1 · HMAC SHA-256 hex, `hmac-sha256=` | `X-Airtable-Content-MAC` | ping only — pull the payload | 📋 |
| HubSpot | 2 · HMAC SHA-256 base64 over `method + uri + body + ts` (v3) | `X-HubSpot-Signature-v3`, `X-HubSpot-Request-Timestamp` | body `.subscriptionType` | 📋 |
| Salesforce | 9 · outbound messages over mTLS (SOAP) | — | SOAP envelope | 🔍 |
| Asana | 1 · HMAC SHA-256 hex; `X-Hook-Secret` handshake | `X-Hook-Signature` | per-event `.action` | 📋 |
| Trello | 7 · HMAC SHA-1 base64 over `body + callbackURL`; HEAD handshake | `X-Trello-Webhook` | body `.action.type` | 📋 |
| monday.com | 5 · JWT; challenge echo on setup | `Authorization` | body `.event.type` | 📋 |
| ClickUp | 1 · HMAC SHA-256 hex | `X-Signature` | body `.event` | 📋 |
| Calendly | 2 · HMAC `t=`/`v1=`, SHA-256 hex | `Calendly-Webhook-Signature` | body `.event` | 📋 |
| Typeform | 1 · HMAC SHA-256 base64, `sha256=` | `Typeform-Signature` | body `.event_type` | 📋 |
| DocuSign | 1 · HMAC SHA-256 base64 | `X-DocuSign-Signature-1` | body `.event` | 📋 |
| Dropbox | 1 · HMAC SHA-256 hex; GET `challenge` echo | `X-Dropbox-Signature` | ping only — pull deltas | 📋 |
| Box | 2 · HMAC SHA-256 base64 over `body + ts`, dual keys | `Box-Signature-Primary`, `Box-Signature-Secondary` | body `.trigger` | 📋 |
| Xero | 1 · HMAC SHA-256 base64 | `x-xero-signature` | body `.events[].eventType` | 📋 |
| QuickBooks | 1 · HMAC SHA-256 base64 | `intuit-signature` | body `.eventNotifications` | 📋 |

---

## Infrastructure & monitoring

| Provider | Scheme | Key headers | Event name from | Status |
|----------|--------|-------------|-----------------|--------|
| AWS SNS | 6 · RSA-SHA256 + cert from `SigningCertURL`; `SubscriptionConfirmation` handshake | `x-amz-sns-message-type` | body `.Type` | 📋 |
| AWS EventBridge | 9 · delivered via API destination / SNS | varies | detail-type | 🔍 |
| Azure Event Grid | 9 · validation handshake + optional key | `aeg-event-type` | body `.eventType` | 🔍 |
| PagerDuty | 2 · HMAC SHA-256 hex, `v1=` | `X-PagerDuty-Signature` | body `.event.event_type` | 📋 |
| Datadog | 9 · user-defined custom headers | user-defined | payload template | 🔍 |
| Grafana | 9 · optional basic auth | `Authorization` | body `.status` | 🔍 |
| BetterStack | 9 · none / custom | — | body | 🔍 |
| Svix | 3 · Standard Webhooks (the reference implementation) | `svix-*` | body `.type` | ✅ ᵍ |
| Hookdeck | 1 · HMAC SHA-256 base64 | `x-hookdeck-signature` | passthrough | 🔍 |

---

## AI & media

| Provider | Scheme | Key headers | Event name from | Status |
|----------|--------|-------------|-----------------|--------|
| OpenAI | 3 · Standard Webhooks | `webhook-id`, `webhook-timestamp`, `webhook-signature` | body `.type` | ✅ ᵍ |
| Replicate | 3 · Standard Webhooks | `webhook-*` | body `.status` | ✅ |
| ElevenLabs | 1 · HMAC SHA-256 hex, `t=`/`v0=` | `ElevenLabs-Signature` | body `.type` | 🔍 |
| Deepgram | 9 · user-defined callback auth | user-defined | body | 🔍 |
| AssemblyAI | 8 · user-defined auth header | user-defined | body `.status` | 🔍 |
| Mux | 2 · HMAC `t=`/`v1=`, SHA-256 hex | `Mux-Signature` | body `.type` | 📋 |
| Cloudinary | 1 · HMAC SHA-1 hex over `body + ts` | `X-Cld-Signature`, `X-Cld-Timestamp` | body `.notification_type` | 🔍 |

---

## CMS & content

| Provider | Scheme | Key headers | Event name from | Status |
|----------|--------|-------------|-----------------|--------|
| Sanity | 2 · HMAC SHA-256 base64url, `t=`/`v1=` | `sanity-webhook-signature` | user-defined projection | 📋 |
| Contentful | 1 · HMAC SHA-256 with signed-header canonicalization | `x-contentful-signature`, `x-contentful-signed-headers` | `X-Contentful-Topic` | 🔍 |
| Storyblok | 1 · HMAC SHA-1 hex | `webhook-signature` | body `.action` | 🔍 |
| Strapi | 9 · user-defined header | user-defined | body `.event` | 📋 |
| Prismic | 8 · shared secret in body | body `.secret` | body `.type` | 📋 |
| WordPress | 9 · plugin-dependent | varies | varies | 🔍 |

---

## Handshakes and challenges

A signature check is not the only thing standing between you and a working
endpoint. Several providers will not deliver anything until you answer a
one-time challenge, and they each do it differently. This is the part most
webhook code forgets, so the provider contract has a dedicated `handshake` hook.

**Handshakes come in two classes, and the order matters.** Some are unsigned,
often because that very request is what establishes the shared secret — they
must be answered before verification, since there is nothing to verify against.
Others are signed, and answering them before verifying is a security hole *and*
a setup failure: Discord probes a new endpoint with a deliberately invalid
signature and refuses to save the URL unless it gets a 401 back.

Providers therefore declare which class they are with `signedHandshake`, and
the handler orders `verify` and `handshake` accordingly. It defaults to
`false`, the safe assumption when no secret exists yet.

| Provider | Trigger | Expected answer | Signed? |
|----------|---------|-----------------|---------|
| Discord (interactions) | POST with `type: 1` (PING) | `{ "type": 1 }` | ✅ must reject a bad signature with 401 |
| Discord (webhook events) | POST with `type: 0` (PING) | bare `204` | ✅ same |
| Slack | POST with `type: "url_verification"` | Echo the `challenge` string | ✅ |
| Zoom | POST with `event: "endpoint.url_validation"` | Return `plainToken` plus its HMAC | ✅ |
| AWS SNS | POST with `x-amz-sns-message-type: SubscriptionConfirmation` | GET the `SubscribeURL` | ✅ cert chain |
| Meta / WhatsApp | `GET ?hub.mode=subscribe&hub.challenge=…&hub.verify_token=…` | Echo `hub.challenge` if the token matches | ❌ token compare only |
| Asana | POST carrying `X-Hook-Secret` | Echo the same header back, then store it as the secret | ❌ this request *creates* the secret |
| Okta | `GET` with `X-Okta-Verification-Challenge` | Echo the value as JSON | ❌ |
| Dropbox | `GET ?challenge=…` | Echo `challenge` as `text/plain` | ❌ |
| Trello | `HEAD` request | `200` with an empty body | ❌ |
| Azure Event Grid | POST with `SubscriptionValidationEvent` | Echo `validationCode` | ❌ |
| monday.com | POST with a `challenge` field | Echo `challenge` | ❌ |
| Google Pub/Sub | none — but the endpoint must return 2xx fast | ack within the deadline or it redelivers | n/a |

---

## Adding a provider

Most providers are a *description*, not an implementation. Families 1, 2, and 3
are one algorithm with four parameters — which headers carry the signature, how
the digest is encoded, what string was signed, and how the secret is decoded —
so `createHmacProvider` supplies the rest: the replay window, secret rotation,
multiple candidate signatures, constant-time comparison, and the error taxonomy.

A family-1 provider in full:

```ts
import { createHmacProvider, MissingSignatureError } from 'webhooks-sdk'

export function acme(options: { secret: string | string[] }) {
  return createHmacProvider({
    id: 'acme',
    name: 'Acme',
    secret: options.secret,
    encoding: 'hex',
    extract: (raw) => {
      const header = raw.header('x-acme-signature')
      if (!header) throw new MissingSignatureError('Missing x-acme-signature')
      return { candidates: [header] }
    },
    content: (_material, raw) => raw.text(),
    event: (raw) => {
      const payload = raw.json<{ id: string; event: string; sent_at: number }>()
      return {
        id: payload.id,
        provider: 'acme',
        type: payload.event,
        timestamp: new Date(payload.sent_at * 1000),
        payload,
        raw,
      }
    },
  })
}
```

Family 2 adds a timestamp: return it from `extract` and fold it into `content`.

```ts
tolerance: 300,
extract: (raw) => {
  const { t, v1 } = parseAcmeHeader(raw.header('x-acme-signature'))
  return { candidates: v1, timestamp: t }
},
content: (material, raw) => `${material.timestamp}.${raw.text()}`,
```

Reach past `createHmacProvider` only when the scheme genuinely is not an HMAC
over a string — asymmetric signatures, certificate chains, JWTs. Those still
compose from the same pieces (`resolveSecrets`, `assertWithinTolerance`,
`matchesAnyHmac`), which is how `standard-webhooks` supports both a symmetric
`v1` and an Ed25519 `v1a` branch.

What a provider PR needs:

1. The factory, in `src/providers/<id>/index.ts`.
2. A `sign<Provider>Webhook` helper so tests can produce real signatures rather
   than mocking verification — a test that stubs the verifier tests nothing.
3. Tests covering: a valid signature, the wrong secret, a body tampered with
   after signing, a missing header, and — where the scheme signs a timestamp —
   a stale one.
4. A subpath entry in `package.json#exports`.
5. A row in this file, with the status moved to ✅.

Verify against the provider's live documentation, not against this table. This
catalog records intent; the docs record truth.
