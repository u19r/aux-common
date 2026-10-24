use std::{fmt, sync::Arc};

use http_request::{HttpClient, TenantHttpClient, Transport};

use crate::HttpPolicy;

/// Explicit opt-in for transports that can uphold a registered HTTP policy.
///
/// Implementors must enforce the approved destination and total request
/// deadline before dispatch and must not follow redirects. The policy
/// executor checks all three capabilities at construction time.
pub trait PolicyBoundTransport: Transport {}

pub(crate) enum BoundClient {
    Restricted(TenantHttpClient),
    Custom(HttpClient),
}

pub(crate) struct BoundPolicy {
    pub(crate) policy: HttpPolicy,
    pub(crate) client: BoundClient,
}

impl fmt::Debug for BoundClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundClient([REDACTED])")
    }
}

#[derive(Clone)]
pub(crate) struct SharedTransport(pub(crate) Arc<dyn PolicyBoundTransport>);

impl fmt::Debug for SharedTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SharedTransport([REDACTED])")
    }
}

impl Transport for SharedTransport {
    fn send(&self, request: http_request::reqwest::Request) -> http_request::TransportFuture {
        self.0.send(request)
    }

    fn redirects_disabled(&self) -> bool {
        self.0.redirects_disabled()
    }

    fn destination_policy_enforced(&self) -> bool {
        self.0.destination_policy_enforced()
    }

    fn deadline_enforced(&self) -> bool {
        self.0.deadline_enforced()
    }
}

impl PolicyBoundTransport for SharedTransport {}
