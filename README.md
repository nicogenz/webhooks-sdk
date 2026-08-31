# webhooks-sdk

One way to verify, parse, and route webhooks from every provider.

Every provider invented its own signature scheme, its own replay window, and
its own setup handshake. The differences are real but almost never interesting,
and getting them subtly wrong fails quietly — a verification bug looks exactly
like "the webhook didn't fire".

```bash
npm install webhooks-sdk
```

Zero dependencies. Web Crypto and `fetch` only, so the same code runs on Node
22+, Cloudflare Workers, Deno, and Bun.

## Quickstart

```ts
import { createWebhookHandler } from 'webhooks-sdk'
import { stripe } from 'webhooks-sdk/stripe'

const handler = createWebhookHandler({
  provider: stripe({ secret: process.env.STRIPE_WEBHOOK_SECRET! }),
  on: {
    'payment_intent.succeeded': async (event) => {
      await fulfill(event.payload.data.object)
    },
    'customer.subscription.deleted': async (event) => {
      await revoke(event.payload.data.object)
    },
  },
})

// Next.js App Router, Hono, Deno, Bun, Workers — anything with a Request.
export const POST = handler.fetch
```

That call verifies the signature, enforces the replay window, parses the body,
and dispatches — returning `401` on a bad signature, `400` on a malformed one,
`500` if your handler throws (so the provider retries), and `200` otherwise.

## Why the raw body matters

Every signature scheme signs the exact bytes on the wire. Parse the body and
re-serialize it and the signature no longer matches, because key order,
whitespace, and unicode escaping all changed. This is the single most common
cause of "verification randomly fails".

The SDK therefore takes the request, not your parsed object, and reads the body
once as bytes. In Express that means mounting the webhook route *before* any
JSON parser:

```ts
import express from 'express'
import { toExpressHandler } from 'webhooks-sdk/express'

// Raw on the webhook path only; JSON everywhere else.
app.post('/webhooks/stripe', express.raw({ type: '*/*' }), toExpressHandler(handler))
app.use(express.json())
```

## Core concepts

### The event envelope

Everything above `payload` is identical for every provider:

```ts
{
  id: 'evt_1abc',                    // used for idempotency
  provider: 'stripe',
  type: 'payment_intent.succeeded',  // provider-native name
  timestamp: Date,
  payload: { … },                    // the provider's own body, untouched
  raw: { headers, body, text(), json() },
}
```

`payload` stays provider-native on purpose. A Stripe `PaymentIntent` and a
GitHub push have nothing in common, and flattening them into a shared shape
would lose information without buying much. A cross-provider `semantic` view
for the domains where it genuinely fits — payments, git, messaging — is planned
as an opt-in layer, not a replacement.

### Standalone verification

The router is optional. When you want the check and nothing else:

```ts
import { verifyStripeWebhook, parseStripeWebhook } from 'webhooks-sdk/stripe'
import { toRawWebhook } from 'webhooks-sdk'

const raw = await toRawWebhook(request)
await verifyStripeWebhook(raw, { secret })  // throws WebhookError on failure
const event = parseStripeWebhook(raw)
```

### Handshakes

Most providers will not deliver anything until you answer a one-time challenge,
and the right order differs. Unsigned challenges — Meta's `hub.challenge`,
Asana's `X-Hook-Secret` — must be answered *before* verification, because the
request is often what establishes the secret. Signed ones must be verified
first: Discord probes a new endpoint with a deliberately invalid signature and
refuses to save the URL unless it receives a 401.

Providers declare which they are, and the handler orders the two calls to
match. A handshake short-circuits before dispatch and reports
`outcome: 'handshake'`, so your event handlers never see it.

### Idempotency

Providers retry on non-2xx, and several deliver at-least-once even when you
succeed. Duplicate deliveries are routine, not an edge case:

```ts
import { memoryIdempotencyStore } from 'webhooks-sdk'

createWebhookHandler({
  provider: stripe({ secret }),
  idempotency: memoryIdempotencyStore(),
  on: { … },
})
```

The in-memory store suits a single long-lived process. On serverless or across
several instances, implement the two-method `IdempotencyStore` interface over
Redis, KV, or a Durable Object — each instance otherwise keeps its own map and
catches nothing.

A suppressed duplicate returns `200`, not an error. Rejecting it would make the
provider redeliver it forever.

### Secret rotation

Pass an array; any match wins. Stripe keeps the previous secret valid for 24
hours after you roll it, and a single-secret implementation has a 24-hour hole:

```ts
stripe({ secret: [process.env.STRIPE_SECRET_NEW!, process.env.STRIPE_SECRET_OLD!] })
```

### One route, many providers

```ts
import { WebhookRouter } from 'webhooks-sdk'

const router = new WebhookRouter({
  providers: {
    stripe: stripe({ secret: process.env.STRIPE_SECRET! }),
    github: github({ secret: process.env.GITHUB_SECRET! }),
  },
})

router.on('stripe', 'charge.refunded', handleRefund)
router.on('github', 'push', handlePush)

// app/api/webhooks/[provider]/route.ts
export const POST = router.fetch
```

The provider is taken from the last path segment by default; override with
`resolve`.

### Errors

Failures are returned, not thrown — `handler.process()` never throws:

```ts
const result = await handler.process(request)

if (!result.ok) {
  console.error(result.error?.code)  // 'invalid_signature' | 'timestamp_out_of_tolerance' | …
}
```

`result.outcome` is one of `handled`, `unhandled`, `duplicate`, `handshake`, or
`failed`. Every `WebhookError` carries a `code`, an HTTP `status`, and an
`isVerificationFailure` flag.

## Framework adapters

| Import | For |
|--------|-----|
| `handler.fetch` | Anything Web-standard: Next.js App Router, Workers, Deno, Bun, Remix |
| `webhooks-sdk/next` | `export const { POST } = toNextRoute(handler)` |
| `webhooks-sdk/nuxt` | `export default defineEventHandler(toNuxtHandler(handler))` |
| `webhooks-sdk/nitro` | `toNitroHandler(handler)` for Nitro routes (Analog, SolidStart, TanStack Start) |
| `webhooks-sdk/h3` | `toH3Handler(handler)` for plain h3 — all three are the same adapter |
| `webhooks-sdk/hono` | `app.post('/hook', toHonoHandler(handler))` |
| `webhooks-sdk/express` | `toExpressHandler(handler)`, plus `captureRawBody` |
| `webhooks-sdk/node` | `toNodeHandler(handler)` for bare `node:http` and the Pages Router |

## Testing

Sign fixtures with the real algorithm instead of stubbing the verifier — a test
that mocks verification tests nothing:

```ts
import { createWebhookRequest, eventRecorder } from 'webhooks-sdk/testing'
import { signStripeWebhook } from 'webhooks-sdk/stripe'

const body = JSON.stringify(event)
const request = createWebhookRequest({
  body,
  headers: { 'stripe-signature': await signStripeWebhook(body, secret) },
})

const recorder = eventRecorder()
const handler = createWebhookHandler({ provider, onEvent: recorder.record })
await handler.process(request)

expect(recorder.types).toEqual(['payment_intent.succeeded'])
```

Inject the clock with `now` to test replay windows without waiting.

## Providers

Shipping today: **Stripe**, **GitHub**, **Discord**, **Twilio**, **Google
Pub/Sub** (which also carries Gmail push, Play RTDN, and Workspace Events),
and **Standard Webhooks** — the last of which covers every Svix-backed vendor,
with named wrappers for **Resend**, **Clerk**, **Polar**, and **Replicate**.

Any other Standard Webhooks vendor works right now without a wrapper:

```ts
import { standardWebhooks } from 'webhooks-sdk/standard-webhooks'

standardWebhooks({ id: 'openai', secret: process.env.OPENAI_WEBHOOK_SECRET! })
```

That covers OpenAI, Dodo, Stytch, Loops, and Svix itself. Both header
generations (`webhook-*` and the older `svix-*`) are accepted, along with the
spec's asymmetric Ed25519 `v1a` signatures.

See [INTEGRATIONS.md](./INTEGRATIONS.md) for the full catalog — roughly 90
providers grouped by the nine signature families that cover almost all of them,
plus the handshake each one expects before it will deliver anything.

Adding a provider is one file and a test fixture; the contract is documented at
the end of that page.

## Roadmap

- **0.1** — core, Stripe, GitHub, Standard Webhooks (+ Resend, Clerk, Polar,
  Replicate), framework adapters, testing utilities
- **0.2** — ✅ the providers that stress the contract: Twilio (signs the public
  endpoint URL, not the body) and Google Pub/Sub push (JWKS plus a nested
  envelope). Next: the rest of tier 1 — Slack, Shopify, GitLab, Linear,
  Paddle, Square
- **0.3** — the rest of the JWKS and certificate-chain families (PayPal,
  AWS SNS, Plaid) on the pluggable key cache that shipped with Pub/Sub
- **0.4** — the opt-in `semantic` layer for payments, git, and messaging
- **Later** — a CLI for replaying captured deliveries against a local endpoint

## License

MIT
