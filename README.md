# aux-common

Shared Rust crates for reusable Aux infrastructure: bounded clients, codecs, caches, metrics,
telemetry, authentication verification, and runtime-neutral authorization and background-job
primitives.

## Authentication and verification

- [`jose-core`](crates/jose-core/README.md) strict asymmetric JWS parsing and verification; no
  claims, issuer, or audience validation.
- [`jwt-decode`](crates/jwt-decode/README.md) full JWT verification with claims, JWKS, and policy
  enforcement.
- [`crypto-hash`](crates/crypto-hash/README.md) SHA-256, HMAC-SHA256, Argon2id passwords, and
  API-key hashes; no reset, rate-limit, or persistence policy.
- [`saml2`](crates/saml2/README.md) strict SAML bindings, metadata, and signature verification
  facade over `xml-security`.
- [`xml-security`](crates/xml-security/README.md) bounded XML 1.0 parsing and reviewed
  exclusive-canonicalization subset for enveloped XMLDSig.
- [`webauthn-core`](crates/webauthn-core/README.md) strict WebAuthn registration and assertion
  verification (ES256-only, `none` attestation).

## Authorization

- `authz-types` shared public authorization domain types.
- `authz-cedar` deterministic Cedar bundle generation and evaluation helpers.
- `authz-runtime` storage-free bitset, snapshot enrichment, step-up, and local Cedar hot path.
  Callers own persistence, service-token validation, HTTP routing, and private orchestration.

## HTTP and AWS

- [`http-request`](crates/http-request/README.md) shared HTTP client, retry, tenant-safety, and
  test transport utilities.
- [`aws-sigv4-signing`](crates/aws-sigv4-signing/README.md) reusable SigV4 request signing helpers.
- `aws-credentials` default-chain credential resolution, including configured profiles through
  AWS CLI credential export; no direct profile parsing or SSO implementation.
- `oauth-dpop` DPoP proof verification and token confirmation contracts; callers own replay
  storage, nonce policy, and access-token validation.

## Buffered writes

[`buffered-writes`](crates/buffered-writes/README.md) bounded write buffering, stable batch
identities, caller-owned sinks, retention providers, and host lifecycle adapters. Callers choose
the retention contract and provide destination idempotency.

## Lambda Web runtime

`lambda-web-runtime` validates reserved listen/runtime addresses, acknowledges readiness after
the caller binds its listener, and bounds server shutdown. Callers own application initialization,
request routing, and background work. This adapter targets the experimental Lambda Web Functions
protocol; it is separate from the classic Lambda extension adapter in `buffered-writes`.

## JavaScript isolation

[`javascript`](crates/javascript/README.md) executes supplied JavaScript functions in fresh, bounded
Wasm instances. Its private QuickJS producer and inspectable artifact remain in this repository.
Callers own admission, application validation and privileged side effects.

## Background jobs

- [`bg-jobs`](crates/bg-jobs/README.md) runtime-neutral durable job engine, v1 codecs,
  scheduling, fairness, batching, and `JobStore` contract.
- `bg-jobs-tokio` Tokio wake-scheduling adapter for the runtime-neutral engine.
- [`bg-jobs-conformance`](crates/bg-jobs-conformance/README.md) reusable store-contract,
  fault-injection, repair, and operation-profile checks.
- [`bg-jobs-http`](crates/bg-jobs-http/README.md) bounded HTTPS requests, destination policy,
  response classification, and the execution-time authorizer boundary.
- [`bg-jobs-aws`](crates/bg-jobs-aws/README.md) AWS SigV4 request authorization for
  `bg-jobs-http`.

A consumer supplies the production `JobStore`, invokes the engine from its chosen
runtime or route layer, and owns authentication, triggers, persistence, and operational policy.

## Portable limits

The core accepts inline payloads up to 950 KiB and checkpoints up to 64 KiB. Backend capabilities
also bound key/value sizes, transaction bytes/keys, range items/bytes, and transaction duration;
an adapter must report those limits truthfully. HTTP request and response bodies have a 950 KiB
ceiling; defaults allow 950 KiB requests and 256 KiB responses. Policies can lower either bound.

JWT compact tokens are capped at 16 KiB, JWKS documents at 1 MiB and 1024 keys. XML/SAML payloads
are capped at 512 KiB with bounded depth, attributes, and namespace declarations. WebAuthn
authenticator data is capped at 16 KiB with bounded CBOR items and depth. Argon2id uses
m=19456 KiB, t=3, p=1, with 16-byte salts and 32-byte output. SigV4 presigned URLs expire after at
most 168 hours.

## Verification

Run `cargo test --workspace --all-features` for the complete local Cargo suite, including
the Cucumber harnesses. In the full development checkout, `just pre-push` also checks formatting,
Clippy, Wasm targets, and QuickJS reproducibility. Live AWS tests require separate configuration.

For the background-job crates, run the package unit/doc tests and the reusable conformance suite
against each consumer adapter. The core and conformance crates are runtime-neutral and have a WASM
compile gate; HTTP and AWS execution require a suitable native runtime. Do not treat the fake
store's green tests as evidence for a remote production backend.
