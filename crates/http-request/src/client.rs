use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_util::{StreamExt, future::BoxFuture};
use http::{HeaderMap, header::CACHE_CONTROL};
use reqwest::{Client, Method, Request, RequestBuilder, Response, StatusCode, Url};
use serde::de::DeserializeOwned;
use tracing::{debug, warn};

use crate::{
    constants::{
        DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_ERROR_BODY_LENGTH_BYTES,
        DEFAULT_MAX_RESPONSE_LENGTH_BYTES, DEFAULT_REQUEST_TIMEOUT, LABEL_METHOD, LABEL_OUTCOME,
        LABEL_STATUS_CLASS, OUTCOME_ERROR, OUTCOME_RETRY, OUTCOME_SUCCESS, STATUS_CLASS_2XX,
        STATUS_CLASS_3XX, STATUS_CLASS_4XX, STATUS_CLASS_5XX, STATUS_CLASS_ERROR,
    },
    error::{HttpRequestError, HttpRequestErrorKind, Result},
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
    redirects_disabled: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RequestAttemptDiagnostics<'a> {
    host: &'a str,
    path_length: usize,
    query_present: bool,
}

pub(crate) fn request_attempt_diagnostics(url: &Url) -> RequestAttemptDiagnostics<'_> {
    RequestAttemptDiagnostics {
        host: url.host_str().unwrap_or_default(),
        path_length: url.path().len(),
        query_present: url.query().is_some(),
    }
}

pub struct HttpClientBuilder {
    builder: reqwest::ClientBuilder,
    retry: RetryConfig,
    transport: Option<Arc<dyn Transport>>,
}

impl fmt::Debug for HttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpClient")
            .field("client", &"[REDACTED]")
            .field("retry", &self.retry)
            .field("transport", &"[REDACTED]")
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

    pub fn build(self) -> Result<HttpClient> {
        let client = self
            .builder
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| HttpRequestError::Build {
                source: err.without_url(),
            })?;
        let transport = self
            .transport
            .unwrap_or_else(|| Arc::new(ReqwestTransport::new(client.clone())));
        let redirects_disabled = transport.redirects_disabled();
        Ok(HttpClient {
            client,
            retry: self.retry,
            transport,
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
        let transport = Arc::new(ReqwestTransport::new(client.clone()));
        Self {
            client,
            retry,
            transport,
            redirects_disabled: false,
        }
    }

    #[must_use]
    pub fn redirects_disabled(&self) -> bool {
        self.redirects_disabled
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
        let request = builder.build().map_err(|err| HttpRequestError::Build {
            source: err.without_url(),
        })?;
        self.execute(request).await
    }

    #[allow(clippy::too_many_lines)]
    pub async fn execute(&self, request: Request) -> Result<HttpResponse> {
        let method = request.method().clone();
        let method_label = method.as_str().to_string();
        let url = request.url().clone();
        let diagnostics = request_attempt_diagnostics(&url);

        let can_retry_method = self.retry.should_retry_method(&method);
        let mut attempt: u32 = 0;
        let can_retry_body = request.try_clone().is_some();
        let mut base_request = Some(request);
        let max_retries = if can_retry_body {
            self.retry.max_retries
        } else {
            0
        };

        loop {
            let request = if attempt == 0 {
                let Some(base) = base_request.take() else {
                    return Err(HttpRequestError::RequestNotCloneable);
                };
                match base.try_clone() {
                    Some(clone) => {
                        base_request = Some(base);
                        clone
                    }
                    None => base,
                }
            } else {
                match base_request.as_ref().and_then(reqwest::Request::try_clone) {
                    Some(clone) => clone,
                    None => return Err(HttpRequestError::RequestNotCloneable),
                }
            };

            debug!(
                attempt,
                method = %method,
                host = diagnostics.host,
                path_length = diagnostics.path_length,
                query_present = diagnostics.query_present,
                "http request attempt"
            );

            let start = Instant::now();
            match self.transport.send(request).await {
                Ok(response) => {
                    let status = response.status();
                    let retrying =
                        can_retry_method && attempt < max_retries && should_retry_status(status);
                    record_metrics(
                        method_label.as_str(),
                        Some(status),
                        if retrying {
                            OUTCOME_RETRY
                        } else {
                            OUTCOME_SUCCESS
                        },
                        start,
                    );

                    if retrying {
                        attempt += 1;
                        metrics_facade::counter!(
                            metrics_facade::CounterMetric::MetricHttpRequestRetries,
                            LABEL_METHOD => method_label.clone()
                        )
                        .increment(1);
                        let delay = retry_delay_for_response(
                            &self.retry,
                            &response,
                            attempt.saturating_sub(1),
                        );
                        warn!(
                            attempt,
                            method = %method,
                            status = %status,
                            delay_ms = delay.as_millis(),
                            "http request retrying after status"
                        );
                        tokio::time::sleep(delay).await;
                        continue;
                    }

                    return Ok(response);
                }
                Err(error) => {
                    let retrying =
                        can_retry_method && attempt < max_retries && should_retry_error(&error);
                    record_metrics(
                        method_label.as_str(),
                        None,
                        if retrying {
                            OUTCOME_RETRY
                        } else {
                            OUTCOME_ERROR
                        },
                        start,
                    );

                    if retrying {
                        attempt += 1;
                        metrics_facade::counter!(
                            metrics_facade::CounterMetric::MetricHttpRequestRetries,
                            LABEL_METHOD => method_label.clone()
                        )
                        .increment(1);
                        let delay = self.retry.backoff_delay(attempt.saturating_sub(1));
                        warn!(
                            attempt,
                            method = %method,
                            error_kind = ?error.kind(),
                            delay_ms = delay.as_millis(),
                            "http request retrying after error"
                        );
                        tokio::time::sleep(delay).await;
                        continue;
                    }

                    metrics_facade::counter!(
                        metrics_facade::CounterMetric::MetricHttpRequestErrors,
                        LABEL_METHOD => method_label.clone()
                    )
                    .increment(1);
                    return Err(error);
                }
            }
        }
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
        self.inner.build().map_err(|err| HttpRequestError::Build {
            source: err.without_url(),
        })
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

pub struct HttpResponse {
    inner: HttpResponseInner,
    max_body_size: Option<usize>,
}

enum HttpResponseInner {
    Reqwest(Response),
    Mock(MockResponse),
}

struct MockResponse {
    status: StatusCode,
    headers: HeaderMap,
    url: Url,
    body: Bytes,
}

impl HttpResponse {
    #[must_use]
    pub fn new(inner: Response, max_body_size: Option<usize>) -> Self {
        Self::from_reqwest(inner).with_max_body_size(max_body_size)
    }

    #[must_use]
    pub fn from_reqwest(inner: Response) -> Self {
        Self {
            inner: HttpResponseInner::Reqwest(inner),
            max_body_size: Some(DEFAULT_MAX_RESPONSE_LENGTH_BYTES),
        }
    }

    #[must_use]
    pub fn from_mock(status: StatusCode, headers: HeaderMap, body: Vec<u8>, url: Url) -> Self {
        Self {
            inner: HttpResponseInner::Mock(MockResponse {
                status,
                headers,
                url,
                body: Bytes::from(body),
            }),
            max_body_size: Some(DEFAULT_MAX_RESPONSE_LENGTH_BYTES),
        }
    }

    #[must_use]
    pub fn with_max_body_size(mut self, max_body_size: Option<usize>) -> Self {
        self.max_body_size = max_body_size;
        self
    }

    pub fn status(&self) -> StatusCode {
        match &self.inner {
            HttpResponseInner::Reqwest(inner) => inner.status(),
            HttpResponseInner::Mock(inner) => inner.status,
        }
    }

    pub fn headers(&self) -> &HeaderMap {
        match &self.inner {
            HttpResponseInner::Reqwest(inner) => inner.headers(),
            HttpResponseInner::Mock(inner) => &inner.headers,
        }
    }

    pub fn url(&self) -> &Url {
        match &self.inner {
            HttpResponseInner::Reqwest(inner) => inner.url(),
            HttpResponseInner::Mock(inner) => &inner.url,
        }
    }

    pub fn error_for_status(self) -> Result<Self> {
        if self.status().is_success() {
            Ok(self)
        } else {
            Err(HttpRequestError::HttpStatus {
                status: self.status(),
                body: None,
            })
        }
    }

    pub fn error_for_status_ref(&self) -> Result<&Self> {
        if self.status().is_success() {
            Ok(self)
        } else {
            Err(HttpRequestError::HttpStatus {
                status: self.status(),
                body: None,
            })
        }
    }

    pub async fn error_for_status_with_body(mut self) -> Result<Self> {
        if self.status().is_success() {
            return Ok(self);
        }
        let status = self.status();
        if self.max_body_size.is_none() {
            self.max_body_size = Some(DEFAULT_MAX_ERROR_BODY_LENGTH_BYTES);
        }
        let body = match self.text().await {
            Ok(body) => Some(body),
            Err(err) => return Err(err),
        };
        Err(HttpRequestError::HttpStatus { status, body })
    }

    /// Extract the underlying response only when no buffered-body limit is set.
    ///
    /// A capped response cannot be converted without discarding its safety
    /// invariant, so callers must stay on `bytes`, `text`, or `json` (or
    /// explicitly opt out with `with_max_body_size(None)`).
    pub fn into_reqwest(self) -> Option<Response> {
        if self.max_body_size.is_some() {
            return None;
        }
        match self.inner {
            HttpResponseInner::Reqwest(inner) => Some(inner),
            HttpResponseInner::Mock(_) => None,
        }
    }

    pub async fn bytes(self) -> Result<Bytes> {
        match self.inner {
            HttpResponseInner::Reqwest(inner) => {
                read_body_with_limit(inner, self.max_body_size).await
            }
            HttpResponseInner::Mock(inner) => read_mock_body(inner, self.max_body_size),
        }
    }

    pub async fn text(self) -> Result<String> {
        let bytes = self.bytes().await?;
        String::from_utf8(bytes.to_vec()).map_err(|err| HttpRequestError::Decode {
            message: err.to_string(),
        })
    }

    pub async fn json<T: DeserializeOwned>(self) -> Result<T> {
        let bytes = self.bytes().await?;
        serde_json::from_slice(&bytes).map_err(|err| HttpRequestError::Decode {
            message: err.to_string(),
        })
    }
}

async fn read_body_with_limit(response: Response, limit: Option<usize>) -> Result<Bytes> {
    if let Some(limit) = limit {
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        let mut size = 0usize;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(HttpRequestError::from)?;
            size = size.saturating_add(chunk.len());
            if size > limit {
                return Err(HttpRequestError::ResponseTooLarge { size, max: limit });
            }
            bytes.extend_from_slice(&chunk);
        }

        Ok(Bytes::from(bytes))
    } else {
        response.bytes().await.map_err(HttpRequestError::from)
    }
}

fn read_mock_body(response: MockResponse, limit: Option<usize>) -> Result<Bytes> {
    if let Some(limit) = limit
        && response.body.len() > limit
    {
        return Err(HttpRequestError::ResponseTooLarge {
            size: response.body.len(),
            max: limit,
        });
    }
    Ok(response.body)
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

fn status_class(status: StatusCode) -> &'static str {
    if status.is_success() {
        STATUS_CLASS_2XX
    } else if status.is_redirection() {
        STATUS_CLASS_3XX
    } else if status.is_client_error() {
        STATUS_CLASS_4XX
    } else if status.is_server_error() {
        STATUS_CLASS_5XX
    } else {
        STATUS_CLASS_ERROR
    }
}

fn record_metrics(method: &str, status: Option<StatusCode>, outcome: &'static str, start: Instant) {
    let status_label = status.map_or(STATUS_CLASS_ERROR, status_class);
    let method_label = method.to_string();
    metrics_facade::counter!(
        metrics_facade::CounterMetric::MetricHttpRequestAttempts,
        LABEL_METHOD => method_label.clone(),
        LABEL_OUTCOME => outcome,
        LABEL_STATUS_CLASS => status_label
    )
    .increment(1);
    metrics_facade::histogram!(
        metrics_facade::HistogramMetric::MetricHttpRequestLatencyMs,
        LABEL_METHOD => method_label,
        LABEL_OUTCOME => outcome,
        LABEL_STATUS_CLASS => status_label
    )
    .record(start.elapsed().as_secs_f64() * 1000.0);
}
