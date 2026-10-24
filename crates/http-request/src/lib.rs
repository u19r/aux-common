//! Shared bounded HTTP client with tenant destination policy.
//!
//! Prefer [`HttpClient`] and [`TenantHttpClient`] over the re-exported
//! `reqwest` types: raw `reqwest` requests bypass redirect, allowlist, DNS,
//! timeout, and body-limit policy. Custom [`Transport`] implementations are
//! trusted code and must preserve the no-redirect, destination, and deadline
//! boundaries.

mod client;
#[cfg(test)]
mod client_tests;
mod constants;
mod error;
#[cfg(test)]
mod error_tests;
mod oauth;
#[cfg(test)]
mod oauth_tests;
mod observer;
#[cfg(test)]
mod observer_tests;
mod response;
#[cfg(test)]
mod response_tests;
mod retry;
mod tenant;
#[cfg(test)]
mod tenant_tests;

pub use client::{
    CachedResponse, HttpClient, HttpClientBuilder, HttpRequestBuilder, Transport, TransportFuture,
    method_telemetry_label,
};
pub use error::{HttpRequestDispatchStatus, HttpRequestError, HttpRequestErrorKind, Result};
pub use oauth::{
    OAuthAuthorizationCodeRequest, OAuthRefreshTokenRequest, OAuthRevocationEndpoint,
    OAuthRevocationRequest, OAuthTokenEndpoint, OAuthTokenResponse, OAuthUserinfoEndpoint,
};
pub use observer::{
    HttpRequestAttempt, HttpRequestAttemptOutcome, HttpRequestObserver, HttpRequestStatusClass,
    NoopHttpRequestObserver, active_http_request_observer, reset_default_http_request_observer,
    set_default_http_request_observer,
};
pub use reqwest::{self, Method, StatusCode, Url, header};
pub use response::HttpResponse;
pub use retry::RetryConfig;
pub use tenant::{
    AllowedDomain, TenantHttpClient, TenantHttpClientBuilder, TenantHttpRequestConfig,
    TenantRequestBuilder,
};
