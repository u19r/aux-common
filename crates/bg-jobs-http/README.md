# bg-jobs-http

Bounded HTTPS request types and execution adapters for durable jobs. Owns trusted destination
policy, request and response size limits, one shared transport, execution-time authorization,
stable attempt identity headers, and body-free HTTP result classification.

## Build a policy and job

```rust
use bytes::Bytes;
use http::{HeaderMap, Method};
use http_request::Url;
use bg_jobs_http::{
    ApprovedEndpoint, HttpExecutor, HttpJob, HttpPolicy, HttpPolicyId, HttpRequest,
    HttpRequestInput,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy_id = HttpPolicyId::try_new("partner-webhook")?;
    let policy = HttpPolicy::builder(policy_id.clone())
        .endpoint(ApprovedEndpoint::exact("api.example.com")?)
        .try_build()?;
    let request = HttpRequest::try_new(HttpRequestInput {
        method: Method::POST,
        url: Url::parse("https://api.example.com/jobs")?,
        headers: HeaderMap::new(),
        body: Bytes::from_static(br#"{"ok":true}"#),
    })?;
    let job = HttpJob::new(policy_id, request);
    let executor = HttpExecutor::try_new([policy])?;

    let _ = (job, executor);
    Ok(())
}
```

`HttpExecutorBuilder::with_transport` accepts a custom transport only when it implements the
public `PolicyBoundTransport` marker from this crate. Implementors must enforce the approved
destination/DNS policy, total request deadline, and no-redirect behavior. These contracts are
reported by methods on `http_request::Transport`: `destination_policy_enforced()`,
`deadline_enforced()`, and `redirects_disabled()`. Each capability defaults to `false`, and the
executor fails closed at construction unless all three are explicitly enabled. Untrusted test
transports remain usable with the lower-level `http-request` client, but cannot be supplied to this
policy-bound executor.

## Security and limits

Only HTTPS URLs with a hostname are accepted. Policies allowlist exact hosts or explicit
subdomains and ports; loopback/IP destinations, credentials in the URL, fragments, and sensitive
headers are rejected. Authorization and other secret material must be added by a registration-owned
`RequestAuthorizer`, not by durable job payload data. Authorizers run through one bounded future
boundary; there is no synchronous authorization escape hatch.

Diagnostics use `HttpRequest::diagnostic_projection(false)`, which returns only bounded header and
body lengths. Requests for a secret-bearing projection are rejected by the library, and the
diagnostic value contains no URL, header content, body content, or credentials.

Request bodies and response bodies are bounded to 950 KiB by the portable core ceiling, with lower
per-policy values allowed. The defaults are a 5-second connect timeout, 20-second request timeout,
950 KiB request and 256 KiB response bounds, and a 15-minute maximum `Retry-After`; configure lower limits when
the endpoint contract allows it. One deadline covers identity insertion, authorization, transport,
and bounded response consumption.

`HttpExecutor::execute` returns a bounded `HttpClassification` containing only a result class,
optional status, retry class/hint, and machine code. It does not retain a body, URL, header value,
credential, or raw transport error. Convert it with `HttpClassification::to_job_outcome` and let
`bg-jobs` perform the durable transition.

## Batch and runtime integration

`BatchJobHandler` and `BatchResultSet` enforce one independent result per claimed item. An omitted
or duplicate item is an invariant failure for that item; a batch-wide response is applied
independently and never invents partial success.
