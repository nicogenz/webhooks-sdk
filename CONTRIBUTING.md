# Contributing

## Getting started

```bash
npm install
npm run check      # typecheck, lint, tests, build, package validation
npm run test:watch
```

## Adding a provider

Most providers are a description, not an implementation — see the contract and
worked example at the end of [INTEGRATIONS.md](./INTEGRATIONS.md).

A provider PR needs all five of these:

1. The factory in `src/providers/<id>/index.ts`.
2. A `sign<Provider>Webhook` helper so tests produce real signatures. **Do not
   mock verification.** A test that stubs the verifier proves nothing about the
   thing most likely to be wrong.
3. Tests covering, at minimum: a valid signature, the wrong secret, a body
   tampered with after signing, a missing header, and — if the scheme signs a
   timestamp — one outside the window.
4. A subpath in `package.json#exports`. `npm run verify:package` checks that it
   actually resolves from an installed tarball.
5. A row in `INTEGRATIONS.md` with the status moved to ✅.

Verify the scheme against the provider's live documentation. The catalog
records intent; their docs record truth.

## Things that will be asked in review

- **Never re-serialize the body.** Signatures cover the exact bytes received.
- **Never compare digests with `===`.** Use the timing-safe helpers.
- **Fail closed.** An unrecognized signature version, a malformed header, or an
  unparseable secret must reject, never fall through to acceptance.
- **Prefer a loud configuration error** over a mysterious signature mismatch.
  A secret that cannot be decoded is a config bug; say so.
- **No dependencies.** Web Crypto and `fetch` only, or it stops running on
  Workers, Deno, and Bun.
- **No Node built-ins in `src/`.** Adapters use structural types so the
  published types need no `@types/node`; the build enforces this with
  `"types": []`.

## Commit and release

Releases are cut from `main` by tagging. `npm run check` and
`npm run verify:package` must pass first; CI runs both.
