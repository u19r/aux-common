# http-request

Shared HTTP client behavior for service-to-service and remote-provider calls.

The crate provides retries, timeouts, typed errors, metrics, response parsing helpers, and optional constrained outbound fetching for untrusted URLs. Keep storage callers explicit about retry policy and response-size limits.

Important files:

- `crates/http-request/src/client.rs`: `HttpClient`, request builder, response handling.
- `crates/http-request/src/retry.rs`: retry and backoff policy.
- `crates/http-request/src/error.rs`: typed failure model.
- `crates/http-request/src/lib.rs`: constrained request metadata helpers used by HTTP-facing storage crates.

## Unit Tests

Use the `Transport` trait and `HttpResponse::from_mock` for deterministic unit tests. A test
transport can return a fixed sequence of `Result<HttpResponse, HttpRequestError>` values without
opening sockets, which lets callers verify retry behavior, headers, request methods, body encoding,
and response parsing.

```rust
use std::{collections::VecDeque, sync::Mutex};

use http::{HeaderMap, StatusCode};
use http_request::{
    HttpClientBuilder, HttpRequestError, HttpResponse, Transport, TransportFuture,
};
use reqwest::{Request, Url};

#[derive(Debug)]
struct SequenceTransport {
    responses: Mutex<VecDeque<Result<HttpResponse, HttpRequestError>>>,
}

impl Transport for SequenceTransport {
    fn send(&self, _request: Request) -> TransportFuture {
        let response = self
            .responses
            .lock()
            .expect("responses lock")
            .pop_front()
            .expect("mock response");
        Box::pin(async move { response })
    }
}

# async fn example() -> Result<(), HttpRequestError> {
let client = HttpClientBuilder::new()
    .with_transport(SequenceTransport {
        responses: Mutex::new(VecDeque::from([Ok(HttpResponse::from_mock(
            StatusCode::OK,
            HeaderMap::new(),
            br#"{"ok":true}"#.to_vec(),
            Url::parse("https://example.test/resource").expect("mock url"),
        ))])),
    })
    .build()
    .expect("client");

let value = client
    .get_json::<serde_json::Value>("https://example.test/resource")
    .await?;
assert_eq!(value["ok"], true);
# Ok(())
# }
```

Prefer this pattern over mocking `reqwest` directly. It exercises the crate's request builder,
retry policy, body-size checks, cache header parsing, and JSON helpers while keeping tests fast.
