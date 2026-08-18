# jose-core

jose-core provides a documented asymmetric JWS profile for applications:
RS256, RS384, ES256, ES384, and EdDSA (Ed25519). It owns strict
protected-header and compact-serialization handling, prepared public-key
verification, and neutral JWK/JWKS projections.

It does not decode claims or enforce issuer, audience, expiry, tenant key
status, KMS/Vault policy, or session lifecycle. Callers provide trusted,
already-authorized key material and apply those policies separately.

Protected headers and compact segments must use canonical unpadded base64url;
duplicate/unknown members, empty kid, unsupported algorithms, mismatched key
families, malformed signatures, and invalid JWK dimensions fail closed.
Protected headers are bounded to 8 KiB, compact JWS inputs to 1 MiB, public
key DER to 8 KiB, and JWK sets reject duplicate key identifiers.
