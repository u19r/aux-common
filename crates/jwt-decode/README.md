# jwt-decode

Reusable signed JWT verification.

Default asymmetric verification allows:

- `RS256`
- `PS256`
- `ES256`
- `EdDSA`

Additional asymmetric algorithms require explicit opt-in:

- `RS384`
- `RS512`
- `PS384`
- `PS512`
- `ES384`

HMAC algorithms require explicit symmetric algorithm policies and are not part of the default
asymmetric policy:

- `HS256`
- `HS384`
- `HS512`

Unsupported in v1:

- `none`
- `ES256K`
- compact tokens with unencoded or detached payloads
- JWS JSON serialization
- header-provided key URLs or key material such as `jku`, `jwk`, `x5u`, `x5c`, `x5t`, and
  `x5t#S256`

## Static JWKS Example

```rust
use std::time::Duration;

use jwt_decode::{
    AllowedAlgorithms, JwksSource, JwtVerifier, TokenKind, VerificationPolicy,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Claims {
    #[serde(flatten)]
    registered: jwt_decode::RegisteredClaims,
    token_type: TokenKind,
    client_id: String,
}

# async fn example(jwks_json: String, token: String) -> Result<(), jwt_decode::JwtDecodeError> {
let verifier = JwtVerifier::builder()
    .jwks_source(JwksSource::json_string(jwks_json)?)
    .allowed_algorithms(AllowedAlgorithms::asymmetric_2026())
    .build()?;

let policy = VerificationPolicy::access_token()
    .issuer("https://issuer.example")?
    .audience("aux-api")?
    .client_id("client-123")?
    .max_issued_age(Duration::from_secs(15 * 60))
    .build()?;

let verified = verifier.verify::<Claims>(&token, &policy).await?;
# let _ = verified;
# Ok(())
# }
```

## Remote JWKS

Use `JwksSource::url("https://issuer.example/.well-known/jwks.json")?` for HTTPS remote key sets.
Remote sources fetch through `http-request::HttpClient` and cache parsed JWKS documents through
`lru-ttl-cache`.

Remote cache keys include both JWKS URL and expected issuer. Unknown `kid` values force one refresh
before returning `KeyNotFound`, which supports normal key rotation without trusting header-provided
URLs.

`JwksCachePolicy` bounds capacity, fallback TTL, refresh TTL, maximum body size, and stale-on-error.
Stale-on-error is short-lived availability behavior; call `JwksSource::invalidate_issuer` when an
issuer or key source is considered compromised.

## Profile Notes

`VerificationPolicy::access_token()` requires `typ = "at+jwt"` by default. Compatibility methods can
allow `application/at+jwt` or a missing access-token header type, but those choices are deliberately
explicit.

`VerificationPolicy::id_token()` validates issuer, audience, expiry, issued-at, nonce when supplied,
and `azp` when multiple audiences are present and a client ID is configured.

`VerificationPolicy::refresh_token()` validates only the signed credential shape. Rotation,
one-time-use checks, idle timeout, family invalidation, and revocation storage remain caller-owned.

## Dangerous Helpers

`dangerous_unverified_claims` is intentionally named as unsafe for authorization decisions. It does
not authenticate, authorize, time-validate, or policy-validate the token.
