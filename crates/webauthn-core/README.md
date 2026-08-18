# webauthn-core

webauthn-core verifies the strict WebAuthn profile over caller-supplied bytes
and a validated relying-party policy. It parses client data and authenticator
data, validates RP ID hashes and flags, rejects extension data, strictly
decodes the supported ES256 COSE key, verifies DER ECDSA signatures, classifies
counter regressions, and validates none attestation objects. Cross-origin
ceremonies require an explicit caller-provided allow-list of normalized
`topOrigin` values; the default policy rejects them.

Policies require canonical base64url challenges containing 16..128 bytes. HTTPS
is required for deployed origins; cleartext HTTP is accepted only for explicit
loopback hosts (`localhost`, `127.0.0.1`, or `::1`). CBOR is preflighted before
decoding with byte, depth, and value-count budgets to keep attacker-controlled
credential and attestation data bounded.

The default profile rejects raw r||s signatures, duplicate or trailing CBOR,
wrong key type/curve/algorithm, malformed credential boundaries, unsupported
attestation formats, and unsupported extensions. The caller owns challenge
freshness/consumption, credential and user binding, tenant policy, atomic
counter persistence, and audit.

## Target support

`wasm32-unknown-unknown` is a compile-only supported target, checked by
`just check-wasm`; this crate has no WASM runtime harness. Verification does
not require runtime entropy, so its P-256 dependency enables only the ECDSA
feature and keeps default features disabled. In particular, the crate does not
enable `getrandom/wasm_js`: browser-specific entropy must remain an explicit
opt-in of the consumer that needs it. `wasm32-wasip1` is not a promised target
in this repository.
