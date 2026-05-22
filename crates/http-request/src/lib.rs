#![doc(hidden)]

mod client;
#[cfg(test)]
mod client_tests;
mod constants;
mod error;
mod oauth;
#[cfg(test)]
mod oauth_tests;
mod retry;
mod tenant;
#[cfg(test)]
mod tenant_tests;

pub use client::{
    CachedResponse, HttpClient, HttpClientBuilder, HttpRequestBuilder, HttpResponse, Transport,
    TransportFuture,
};
pub use error::{HttpRequestError, HttpRequestErrorKind, Result};
pub use oauth::{
    OAuthAuthorizationCodeRequest, OAuthRefreshTokenRequest, OAuthRevocationEndpoint,
    OAuthRevocationRequest, OAuthTokenEndpoint, OAuthTokenResponse, OAuthUserinfoEndpoint,
};
pub use reqwest::{self, Method, StatusCode, Url, header};
pub use retry::RetryConfig;
pub use tenant::{
    AllowedDomain, TenantHttpClient, TenantHttpClientBuilder, TenantHttpRequestConfig,
    TenantRequestBuilder,
};
