# Security policy

This library sits on a trust boundary: it decides whether an inbound HTTP
request really came from the provider it claims to. Bugs here are security
bugs, not correctness bugs.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through
[GitHub Security Advisories](https://github.com/nicogenz/webhooks-sdk/security/advisories/new).

Expect an acknowledgement within 72 hours and an assessment within 7 days. If a
fix is warranted, a patched version is published before the advisory is made
public, and you will be credited unless you ask otherwise.

### In scope

- Any way to make `verify` accept a request the provider did not sign
- Timing characteristics that leak secret or signature material
- A replay being accepted inside a configured tolerance window
- Deduplication being bypassed, or an event id being attacker-controlled
- Crashes reachable from an unauthenticated request

### Out of scope

- Vulnerabilities in the webhook providers themselves — report those upstream
- Secrets leaked through your own logs, error reporting, or configuration
- Denial of service from unbounded request bodies; bound those at your edge or
  server before the handler runs

## What this library does and does not do

Being explicit, because the gap between the two is where incidents happen.

**It does:**

- Verify signatures against the exact bytes received, never a re-serialization
- Compare digests in constant time, and reject malformed encodings rather than
  treating two undecodable values as equal
- Enforce a replay window for every scheme that signs a timestamp
- Refuse to deduplicate on a blank event id, because a collapsed key would
  silently suppress unrelated deliveries and acknowledge them with a 200
- Answer provider handshakes in the order that provider requires, verifying
  signed challenges before responding

**It does not:**

- Protect you if your signing secret leaks. Rotate it; every provider here
  accepts an array of secrets so you can roll without downtime.
- Guarantee exactly-once delivery. Providers retry, and the built-in
  idempotency store is per-process — on serverless or multi-instance
  deployments you must supply a shared one.
- Provide replay protection for schemes that sign no timestamp (family 1 in
  [INTEGRATIONS.md](./INTEGRATIONS.md), including GitHub). Pair those with a
  persistent idempotency store.
- Authorize anything. A verified webhook proves origin, not that the described
  action should be permitted for the account it names.
- Validate payload contents. Treat every field as untrusted input.

## Cryptographic notes

Verification uses Web Crypto exclusively — no vendored crypto, no
dependencies. HMAC comparisons run over decoded bytes so that hex casing and
base64 padding cannot cause a false mismatch, and both the secret and the
candidate loops run to completion so the number of configured secrets is not
observable through response timing.

Signature length is not concealed. It is fixed per algorithm and public.
