# bg-jobs-aws

`bg-jobs-aws` is the AWS SigV4 request-authorizer adapter for `bg-jobs-http`. It signs an approved
HTTP request at execution time with the shared `aws-sigv4-signing` signer and the selected
`CredentialSource`.

## Attach SigV4 to an HTTP policy

Credential resolution is deferred until an attempt is authorized. The default chain can resolve
credentials from the shared AWS provider implementation; static credentials are useful only when
the consuming application has a controlled secret source.

The same policy wiring is kept in the compile-checked [`examples/quickstart.rs`](examples/quickstart.rs)
file.

```rust
use bg_jobs_aws::{CredentialSource, SigV4Authorizer};
use bg_jobs_http::{ApprovedEndpoint, HttpExecutor, HttpPolicy, HttpPolicyId};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy_id = HttpPolicyId::try_new("signed-api")?;
    let authorizer = SigV4Authorizer::try_new(
        "eu-west-1",
        "execute-api",
        CredentialSource::DefaultChain,
    )?;
    let policy = HttpPolicy::builder(policy_id)
        .endpoint(ApprovedEndpoint::exact("api.example.com")?)
        .authorizer(authorizer)
        .try_build()?;
    let _executor = HttpExecutor::try_new([policy])?;
    Ok(())
}
```

The executor validates HTTPS, policy approval, request limits, and the attempt deadline before it
invokes the authorizer. Signing then receives the method, approved URL, non-sensitive headers, and
body. The HTTP boundary preserves its stable idempotency/attempt headers and rejects an authorizer
that changes them. Credential values, signed headers, and signer diagnostics do not enter durable
job values, telemetry, or typed errors.

## Operational boundary

Use `CredentialSource::DefaultChain` for the provider-owned chain or construct a static source in a
controlled secret-management boundary. Do not put credentials, bearer tokens, or provider config
references in an `HttpRequest` body or durable `bg-jobs` payload. The private signing operation
exposes only typed `SigV4AuthorizerError` categories; the `RequestAuthorizer` implementation maps
them to the safe `AuthorizationErrorKind` used by `bg-jobs-http`.

This crate owns no route, retry loop, scheduler, or persistence. The consuming application decides
how to invoke `HttpExecutor`, how to turn classification into a `JobOutcome`, and which production
`JobStore` adapter and runtime to use.
