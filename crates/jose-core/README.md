# jose-core

Asymmetric JWS profile for applications:
RS256, RS384, ES256, ES384, and EdDSA (Ed25519). Strict
protected-header and compact-serialization handling, prepared public-key
verification, and neutral JWK/JWKS projections.

Does not decode claims or enforce issuer, audience, expiry, tenant key
status, KMS/Vault policy, or session lifecycle. Callers provide trusted,
already-authorized key material and apply those policies separately.

Protected headers and compact segments must use canonical un-padded base64url;
duplicate/unknown members, empty kid, unsupported algorithms, mismatched key
families, malformed signatures, and invalid JWK dimensions fail closed.
Protected headers are bounded to 8 KiB, compact JWS inputs to 1 MiB, public
key DER to 8 KiB, and JWK sets reject duplicate key identifiers.


Compact nested-JWT encryption supports RSA-OAEP-256 and A256GCM with
`cty: JWT` and a recipient `kid`. `JweRecipient::try_new` accepts authorized
2048–4096-bit RSA SPKI DER and bounded nonempty key IDs. Each encryption uses
a fresh zeroized 32-byte CEK and 12-byte nonce; the protected header is GCM AAD.
The input must be an already signed, three-segment compact JWT of at most
64 KiB. This primitive does not verify that inner signature or decide which
recipient is authorized. The caller signs first, owns recipient registration,
rotation and expiry, and must fail if required encryption cannot complete.
No decryption, key retrieval or plaintext fallback is provided here.
