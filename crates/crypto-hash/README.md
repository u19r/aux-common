# crypto-hash

`crypto-hash` contains small, model-neutral hashing primitives for
applications. It implements SHA-256, HMAC-SHA256, salted SHA3-512
API-key hashes, and an explicit Argon2id password policy.

The crate does not own persistence, password-reset or rate-limit decisions,
audit events, scheduling, or tenant policy. Password verification is strict by
default: Argon2id version 19 with 19,456 KiB, three iterations, one lane, a
16-byte salt, and a 32-byte output. The bounded `bounded_legacy`
policy is opt-in for existing records and must remain an application migration
decision.

Malformed encodings, unsupported algorithms, and policy mismatches return a
typed error or `false`; inputs are not echoed in errors or debug output.
