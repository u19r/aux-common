use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::future::BoxFuture;
use http::{HeaderMap, header::CACHE_CONTROL};
use reqwest::{Client, Method, Request, RequestBuilder, StatusCode, Url};
use serde::de::DeserializeOwned;
use tracing::{debug, warn};

use crate::{
    constants::{DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT},
    error::{HttpRequestError, HttpRequestErrorKind, Result},
    observer::{HttpRequestAttempt, HttpRequestObserver, active_http_request_observer},
    response::HttpResponse,
    retry::RetryConfig,
};

pub type TransportFuture = BoxFuture<'static, Result<HttpResponse>>;

pub trait Transport: Send + Sync + std::fmt::Debug {
    fn send(&self, request: Request) -> TransportFuture;

    /// Reports whether this transport guarantees that it will not follow
    /// HTTP redirects.
    ///
    /// Custom transports default to `false`; callers must opt in only when
    /// the implementation enforces the same no-redirect boundary as the
    /// built-in reqwest transport.
    fn redirects_disabled(&self) -> bool {
        false
    }

    /// Reports whether this transport enforces the caller's approved
    /// destination policy before dispatch.
    ///
    /// Custom transports default to `false`; callers must opt in only when
    /// the implementation enforces the same destination boundary as the
    /// built-in tenant client.
    fn destination_policy_enforced(&self) -> bool {
        false
    }

    /// Reports whether this transport enforces the request's total deadline.
    ///
    /// Custom transports default to `false`; callers must opt in only when
    /// the implementation bounds connection, response, and body work by the
    /// request deadline.
    fn deadline_enforced(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ReqwestTransport {
    client: Client,
}

impl ReqwestTransport {
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }
}

impl Transport for ReqwestTransport {
    fn send(&self, request: Request) -> TransportFuture {
        let client = self.client.clone();
        Box::pin(async move {
            let response = client
                .execute(request)
                .await
                .map_err(HttpRequestError::from)?;
            Ok(HttpResponse::from_reqwest(response))
        })
    }

    fn redirects_disabled(&self) -> bool {
        true
    }
}

#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    retry: RetryConfig,
    transport: Arc<dyn Transport>,
    observer: Option<Arc<dyn HttpRequestObserver>>,
    redirects_disabled: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RequestAttemptDiagnostics {
    host_present: bool,
    path_length: usize,
    query_present: bool,
}

pub(crate) fn request_attempt_diagnostics(url: &Url) -> RequestAttemptDiagnostics {
    RequestAttemptDiagnostics {
        host_present: url.host_str().is_some(),
        path_length: url.path().len(),
        query_present: url.query().is_some(),
    }
}

pub struct HttpClientBuilder {
    builder: reqwest::ClientBuilder,
    retry: RetryConfig,
    transport: Option<Arc<dyn Transport>>,
    observer: Option<Arc<dyn HttpRequestObserver>>,
}

impl fmt::Debug for HttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpClient")
            .field("client", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("transport", &"[REDACTED]")
            .field("observer_configured", &self.observer.is_some())
            .field("redirects_disabled", &self.redirects_disabled)
            .finish()
    }
}

impl fmt::Debug for HttpClientBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpClientBuilder")
            .field("builder", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("transport_configured", &self.transport.is_some())
            .field("observer_configured", &self.observer.is_some())
            .finish()
    }
}

impl HttpClientBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            builder: Client::builder()
                .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
                .timeout(DEFAULT_REQUEST_TIMEOUT),
            retry: RetryConfig::default(),
            transport: None,
            observer: None,
        }
    }

    /// Keep large downloads streaming with bounded connection and idle reads.
    /// Unlike the default whole-request deadline, the read deadline resets as
    /// bytes arrive. Callers own any deadline for the complete operation.
    #[must_use]
    pub fn for_streaming() -> Self {
        Self {
            builder: Client::builder()
                .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
                .read_timeout(DEFAULT_REQUEST_TIMEOUT),
            retry: RetryConfig::default(),
            transport: None,
            observer: None,
        }
    }

    #[must_use]
    pub fn retry(mut self, retry: RetryConfig) -> Self {
        self.retry = retry;
        self
    }

    #[must_use]
    pub fn with_reqwest_builder<F>(mut self, f: F) -> Self
    where F: FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        self.builder = f(self.builder);
        self
    }

    #[must_use]
    pub fn with_transport<T>(mut self, transport: T) -> Self
    where T: Transport + 'static {
        self.transport = Some(Arc::new(transport));
        self
    }

    #[must_use]
    pub fn with_observer<O>(mut self, observer: O) -> Self
    where O: HttpRequestObserver {
        self.observer = Some(Arc::new(observer));
        self
    }

    #[must_use]
    pub fn with_shared_observer(mut self, observer: Arc<dyn HttpRequestObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    pub fn build(self) -> Result<HttpClient> {
        let client = self
            .builder
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| HttpRequestError::Build)?;
        let transport = self
            .transport
            .unwrap_or_else(|| Arc::new(ReqwestTransport::new(client.clone())));
        let redirects_disabled = transport.redirects_disabled();
        Ok(HttpClient {
            client,
            retry: self.retry,
            transport,
            observer: self.observer,
            redirects_disabled,
        })
    }
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient {
    pub fn new() -> Result<Self> {
        HttpClientBuilder::new().build()
    }

    #[must_use]
    pub fn builder() -> HttpClientBuilder {
        HttpClientBuilder::new()
    }

    #[must_use]
    pub fn with_client(client: Client, retry: RetryConfig) -> Self {
        Self::with_client_and_observer(client, retry, None)
    }

    #[must_use]
    pub(crate) fn with_client_and_observer(
        client: Client,
        retry: RetryConfig,
        observer: Option<Arc<dyn HttpRequestObserver>>,
    ) -> Self {
        let transport = Arc::new(ReqwestTransport::new(client.clone()));
        Self {
            client,
            retry,
            transport,
            observer,
            redirects_disabled: false,
        }
    }

    #[must_use]
    pub fn redirects_disabled(&self) -> bool {
        self.redirects_disabled
    }

    /// Whether this client may transparently retry a request with this method.
    /// Protocol adapters use this capability to keep attempt ownership
    /// explicit.
    pub fn can_retry_method(&self, method: &Method) -> bool {
        self.retry.max_retries > 0 && self.retry.should_retry_method(method)
    }

    #[must_use]
    pub fn inner(&self) -> &Client {
        &self.client
    }

    pub fn request<U: reqwest::IntoUrl>(&self, method: Method, url: U) -> HttpRequestBuilder {
        HttpRequestBuilder::new(self.clone(), self.client.request(method, url))
    }

    pub fn get<U: reqwest::IntoUrl>(&self, url: U) -> HttpRequestBuilder {
        HttpRequestBuilder::new(self.clone(), self.client.get(url))
    }

    pub fn post<U: reqwest::IntoUrl>(&self, url: U) -> HttpRequestBuilder {
        HttpRequestBuilder::new(self.clone(), self.client.post(url))
    }

    pub fn put<U: reqwest::IntoUrl>(&self, url: U) -> HttpRequestBuilder {
        HttpRequestBuilder::new(self.clone(), self.client.put(url))
    }

    pub fn patch<U: reqwest::IntoUrl>(&self, url: U) -> HttpRequestBuilder {
        HttpRequestBuilder::new(self.clone(), self.client.patch(url))
    }

    pub fn delete<U: reqwest::IntoUrl>(&self, url: U) -> HttpRequestBuilder {
        HttpRequestBuilder::new(self.clone(), self.client.delete(url))
    }

    pub fn head<U: reqwest::IntoUrl>(&self, url: U) -> HttpRequestBuilder {
        HttpRequestBuilder::new(self.clone(), self.client.head(url))
    }

    pub async fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        let response = self.get(url).send().await?;
        let response = response.error_for_status_with_body().await?;
        response.json().await
    }

    pub async fn get_json_with_bearer<T: DeserializeOwned>(
        &self,
        url: &str,
        token: &str,
    ) -> Result<T> {
        let response = self.get(url).bearer_auth(token).send().await?;
        let response = response.error_for_status_with_body().await?;
        response.json().await
    }

    pub async fn get_json_with_cache<T: DeserializeOwned>(
        &self,
        url: &str,
        fallback_ttl: Duration,
    ) -> Result<CachedResponse<T>> {
        let response = self.get(url).send().await?;
        let response = response.error_for_status_with_body().await?;
        let ttl = cache_ttl_from_headers(response.headers(), fallback_ttl);
        let expires_at =
            Instant::now()
                .checked_add(ttl)
                .ok_or(HttpRequestError::CacheTtlOverflow {
                    seconds: ttl.as_secs(),
                })?;
        let value = response.json().await?;
        Ok(CachedResponse { value, expires_at })
    }

    pub async fn post_form<T: DeserializeOwned, F: serde::Serialize + ?Sized>(
        &self,
        url: &str,
        form: &F,
    ) -> Result<T> {
        let response = self.post(url).form(form).send().await?;
        let response = response.error_for_status_with_body().await?;
        response.json().await
    }

    pub async fn post_json<T: DeserializeOwned, B: serde::Serialize + ?Sized>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<T> {
        let response = self.post(url).json(body).send().await?;
        let response = response.error_for_status_with_body().await?;
        response.json().await
    }

    pub async fn execute_request(&self, builder: RequestBuilder) -> Result<HttpResponse> {
        let request = builder.build().map_err(|_| HttpRequestError::Build)?;
        self.execute(request).await
    }

    pub async fn execute(&self, request: Request) -> Result<HttpResponse> {
        let mut attempts = RequestAttempts::new(request, &self.retry, self.observer.as_ref());
        loop {
            let request = attempts.next_request()?;
            let start = Instant::now();
            if let Some(result) = attempts
                .finish(self.transport.send(request).await, start)
                .await
            {
                return result;
            }
        }
    }
}

struct RequestAttempts<'a> {
    first_request: Option<Request>,
    base_request: Option<Request>,
    retry: &'a RetryConfig,
    observer: Option<&'a Arc<dyn HttpRequestObserver>>,
    method_label: &'static str,
    diagnostics: RequestAttemptDiagnostics,
    max_retries: u32,
    attempt: u32,
}

impl<'a> RequestAttempts<'a> {
    fn new(
        request: Request,
        retry: &'a RetryConfig,
        observer: Option<&'a Arc<dyn HttpRequestObserver>>,
    ) -> Self {
        let first_request = request.try_clone();
        let can_retry = first_request.is_some() && retry.should_retry_method(request.method());
        let max_retries = if can_retry { retry.max_retries } else { 0 };
        Self {
            retry,
            observer,
            method_label: method_telemetry_label(request.method()),
            diagnostics: request_attempt_diagnostics(request.url()),
            max_retries,
            attempt: 0,
            first_request,
            base_request: Some(request),
        }
    }

    fn next_request(&mut self) -> Result<Request> {
        let request = if self.attempt == 0 {
            self.first_request
                .take()
                .or_else(|| self.base_request.take())
                .ok_or(HttpRequestError::RequestNotCloneable)?
        } else {
            self.base_request
                .as_ref()
                .and_then(reqwest::Request::try_clone)
                .ok_or(HttpRequestError::RequestNotCloneable)?
        };
        debug!(
            attempt = self.attempt,
            method = self.method_label,
            host_present = self.diagnostics.host_present,
            path_length = self.diagnostics.path_length,
            query_present = self.diagnostics.query_present,
            "http request attempt"
        );
        Ok(request)
    }

    async fn finish(
        &mut self,
        result: Result<HttpResponse>,
        start: Instant,
    ) -> Option<Result<HttpResponse>> {
        let status = result.as_ref().ok().map(HttpResponse::status);
        let retrying = self.attempt < self.max_retries
            && (status.is_some_and(should_retry_status)
                || result.as_ref().is_err_and(should_retry_error));
        let observation = HttpRequestAttempt::new(
            self.method_label,
            status,
            self.attempt,
            retrying,
            start.elapsed(),
        );
        match self.observer {
            Some(observer) => observer.observe_attempt(observation),
            None => active_http_request_observer().observe_attempt(observation),
        }
        if !retrying {
            return Some(result);
        }

        self.attempt += 1;
        let attempt = self.attempt;
        let (status, error_kind, delay) = match result {
            Ok(response) => {
                let status = response.status();
                let delay =
                    retry_delay_for_response(self.retry, &response, attempt.saturating_sub(1));
                (Some(status), None, delay)
            }
            Err(error) => (
                None,
                Some(error.kind()),
                self.retry.backoff_delay(attempt.saturating_sub(1)),
            ),
        };
        self.wait_for_retry(attempt, status, error_kind, delay)
            .await;
        None
    }

    async fn wait_for_retry(
        &self,
        attempt: u32,
        status: Option<StatusCode>,
        error_kind: Option<HttpRequestErrorKind>,
        delay: Duration,
    ) {
        if let Some(status) = status {
            warn!(
                attempt,
                method = self.method_label,
                status = %status,
                delay_ms = delay.as_millis(),
                "http request retrying after status"
            );
        } else if let Some(error_kind) = error_kind {
            warn!(
                attempt,
                method = self.method_label,
                error_kind = ?error_kind,
                delay_ms = delay.as_millis(),
                "http request retrying after error"
            );
        }
        tokio::time::sleep(delay).await;
    }
}

pub struct HttpRequestBuilder {
    client: HttpClient,
    inner: RequestBuilder,
}

impl fmt::Debug for HttpRequestBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRequestBuilder")
            .field("client", &"[REDACTED]")
            .field("request", &"[REDACTED]")
            .finish()
    }
}

impl HttpRequestBuilder {
    fn new(client: HttpClient, inner: RequestBuilder) -> Self {
        Self { client, inner }
    }

    #[must_use]
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        reqwest::header::HeaderName: TryFrom<K>,
        <reqwest::header::HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        reqwest::header::HeaderValue: TryFrom<V>,
        <reqwest::header::HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.inner = self.inner.header(key, value);
        self
    }

    #[must_use]
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.inner = self.inner.headers(headers);
        self
    }

    #[must_use]
    pub fn query<T: serde::Serialize + ?Sized>(mut self, query: &T) -> Self {
        self.inner = self.inner.query(query);
        self
    }

    #[must_use]
    pub fn json<T: serde::Serialize + ?Sized>(mut self, json: &T) -> Self {
        self.inner = self.inner.json(json);
        self
    }

    #[must_use]
    pub fn form<T: serde::Serialize + ?Sized>(mut self, form: &T) -> Self {
        self.inner = self.inner.form(form);
        self
    }

    #[must_use]
    pub fn body<B: Into<reqwest::Body>>(mut self, body: B) -> Self {
        self.inner = self.inner.body(body);
        self
    }

    #[must_use]
    pub fn bearer_auth<T: std::fmt::Display>(mut self, token: T) -> Self {
        self.inner = self.inner.bearer_auth(token);
        self
    }

    #[must_use]
    pub fn basic_auth<U, P>(mut self, username: U, password: Option<P>) -> Self
    where
        U: std::fmt::Display,
        P: std::fmt::Display,
    {
        self.inner = self.inner.basic_auth(username, password);
        self
    }

    #[must_use]
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    pub fn build(self) -> Result<Request> {
        self.inner.build().map_err(|_| HttpRequestError::Build)
    }

    pub fn try_clone(&self) -> Option<Self> {
        self.inner
            .try_clone()
            .map(|inner| Self::new(self.client.clone(), inner))
    }

    pub async fn send(self) -> Result<HttpResponse> {
        self.client.execute_request(self.inner).await
    }
}

fn should_retry_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::REQUEST_TIMEOUT
            | StatusCode::LOCKED
            | StatusCode::TOO_EARLY
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

pub(crate) fn retry_delay_for_response(
    retry: &RetryConfig,
    response: &HttpResponse,
    retry_attempt: u32,
) -> Duration {
    response
        .headers()
        .get(http::header::RETRY_AFTER)
        .and_then(parse_retry_after)
        .map(|delay| delay.min(retry.max_delay))
        .unwrap_or_else(|| retry.backoff_delay(retry_attempt))
}

fn parse_retry_after(value: &http::HeaderValue) -> Option<Duration> {
    let raw = value.to_str().ok()?.trim();
    if let Ok(seconds) = raw.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let retry_at = httpdate::parse_http_date(raw).ok()?;
    Some(
        retry_at
            .duration_since(std::time::SystemTime::now())
            .unwrap_or(Duration::ZERO),
    )
}

fn cache_ttl_from_headers(headers: &HeaderMap, fallback: Duration) -> Duration {
    if let Some(cache_control) = headers.get(CACHE_CONTROL)
        && let Ok(cache_control) = cache_control.to_str()
    {
        let directives = cache_control
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();

        if directives
            .iter()
            .any(|directive| directive == "no-store" || directive == "no-cache")
        {
            return Duration::ZERO;
        }

        for part in directives {
            if let Some(rest) = part.strip_prefix("max-age=")
                && let Ok(seconds) = rest.parse::<u64>()
            {
                return Duration::from_secs(seconds);
            }
        }
    }
    fallback
}

pub struct CachedResponse<T> {
    pub value: T,
    pub expires_at: Instant,
}

impl<T> CachedResponse<T> {
    pub fn expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

fn should_retry_error(error: &HttpRequestError) -> bool {
    matches!(
        error.kind(),
        HttpRequestErrorKind::Timeout
            | HttpRequestErrorKind::Connect
            | HttpRequestErrorKind::Request
    )
}

/// Returns a bounded, low-cardinality label for an HTTP method.
///
/// Standard methods retain their protocol names. Extension methods are
/// reported as `OTHER` so attacker-controlled method bytes never enter
/// telemetry or diagnostics.
pub fn method_telemetry_label(method: &Method) -> &'static str {
    if *method == Method::GET {
        "GET"
    } else if *method == Method::POST {
        "POST"
    } else if *method == Method::PUT {
        "PUT"
    } else if *method == Method::PATCH {
        "PATCH"
    } else if *method == Method::DELETE {
        "DELETE"
    } else if *method == Method::HEAD {
        "HEAD"
    } else if *method == Method::OPTIONS {
        "OPTIONS"
    } else if *method == Method::TRACE {
        "TRACE"
    } else if *method == Method::CONNECT {
        "CONNECT"
    } else {
        "OTHER"
    }
}
