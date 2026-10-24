use std::{fmt, num::NonZeroUsize, sync::Arc, time::Duration};

use bg_jobs::{MAX_INLINE_PAYLOAD_BYTES, ValidationError};
use http::HeaderName;
use url::Url;

use crate::{
    RequestAuthorizer,
    authorizer::NoopAuthorizer,
    constants::{
        DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_REQUEST_TIMEOUT,
        DEFAULT_RETRY_AFTER_FALLBACK, DEFAULT_RETRY_AFTER_MAX, MAX_POLICY_ID_BYTES,
    },
    error::HttpJobError,
    request::{is_caller_forbidden_header, is_safe_url},
};

/// An immutable registration identifier for a trusted HTTP policy.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HttpPolicyId(String);

impl HttpPolicyId {
    pub fn try_new(value: impl AsRef<str>) -> Result<Self, ValidationError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(ValidationError::Empty {
                field: "HTTP policy ID",
            });
        }
        if value.len() > MAX_POLICY_ID_BYTES {
            return Err(ValidationError::TooLong {
                field: "HTTP policy ID",
                maximum: MAX_POLICY_ID_BYTES,
                actual: value.len(),
            });
        }
        if value.chars().any(char::is_control) {
            return Err(ValidationError::InvalidText {
                field: "HTTP policy ID",
            });
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for HttpPolicyId {
    type Error = ValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl fmt::Display for HttpPolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A trusted destination approved by registration, never by job payload data.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ApprovedEndpoint {
    host: String,
    port: u16,
    allow_subdomains: bool,
}

impl fmt::Debug for ApprovedEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedEndpoint")
            .field("host_present", &true)
            .field("port", &self.port)
            .field("allow_subdomains", &self.allow_subdomains)
            .finish()
    }
}

impl ApprovedEndpoint {
    pub fn exact(host: impl AsRef<str>) -> Result<Self, ValidationError> {
        Self::try_new(host, false)
    }

    pub fn with_subdomains(host: impl AsRef<str>) -> Result<Self, ValidationError> {
        Self::try_new(host, true)
    }

    pub fn exact_on_port(host: impl AsRef<str>, port: u16) -> Result<Self, ValidationError> {
        Self::try_new_with_port(host, port, false)
    }

    fn try_new(host: impl AsRef<str>, allow_subdomains: bool) -> Result<Self, ValidationError> {
        Self::try_new_with_port(host, 443, allow_subdomains)
    }

    fn try_new_with_port(
        host: impl AsRef<str>,
        port: u16,
        allow_subdomains: bool,
    ) -> Result<Self, ValidationError> {
        let host = host.as_ref().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || host.chars().any(char::is_control) {
            return Err(ValidationError::InvalidText {
                field: "approved endpoint host",
            });
        }
        if host.contains(['@', '/', '?', '#', '[', ']', ':', ' ']) {
            return Err(ValidationError::InvalidText {
                field: "approved endpoint host",
            });
        }
        if is_ip_host(&host) {
            return Err(ValidationError::InvalidValue {
                field: "approved endpoint host",
            });
        }
        if port == 0 {
            return Err(ValidationError::InvalidValue {
                field: "approved endpoint port",
            });
        }
        Ok(Self {
            host,
            port,
            allow_subdomains,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub const fn allows_subdomains(&self) -> bool {
        self.allow_subdomains
    }

    pub fn matches(&self, url: &Url) -> bool {
        let Some(host) = url.host_str() else {
            return false;
        };
        let Some(port) = url.port_or_known_default() else {
            return false;
        };
        let host = host.trim_end_matches('.');
        let host_match = host.eq_ignore_ascii_case(&self.host)
            || (self.allow_subdomains && subdomain_matches(host, &self.host));
        host_match && port == self.port
    }
}

fn subdomain_matches(host: &str, approved_host: &str) -> bool {
    if host.len() <= approved_host.len() + 1 {
        return false;
    }
    let mut host_bytes = host.bytes().rev();
    for approved_byte in approved_host.bytes().rev() {
        let Some(host_byte) = host_bytes.next() else {
            return false;
        };
        if !host_byte.eq_ignore_ascii_case(&approved_byte) {
            return false;
        }
    }
    host_bytes.next() == Some(b'.')
}

fn is_ip_host(host: &str) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .is_some_and(|inner| inner.parse::<std::net::IpAddr>().is_ok())
    {
        return true;
    }
    Url::parse(&format!("https://{host}/"))
        .ok()
        .is_some_and(|url| {
            matches!(
                url.host(),
                Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_))
            )
        })
}

/// Immutable transport and classification policy compiled at registration.
pub struct HttpPolicy {
    id: HttpPolicyId,
    endpoints: Vec<ApprovedEndpoint>,
    connect_timeout: Duration,
    request_timeout: Duration,
    max_request_bytes: NonZeroUsize,
    max_response_bytes: NonZeroUsize,
    retry_after_max: Duration,
    retry_after_fallback: Duration,
    idempotency_header: HeaderName,
    attempt_header: HeaderName,
    authorizer: Arc<dyn RequestAuthorizer>,
}

impl fmt::Debug for HttpPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpPolicy")
            .field("id", &self.id)
            .field("endpoints", &self.endpoints)
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("max_request_bytes", &self.max_request_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("retry_after_max", &self.retry_after_max)
            .field("retry_after_fallback", &self.retry_after_fallback)
            .field("idempotency_header", &self.idempotency_header)
            .field("attempt_header", &self.attempt_header)
            .field("authorizer", &"[REDACTED]")
            .finish()
    }
}

impl HttpPolicy {
    pub fn builder(id: HttpPolicyId) -> HttpPolicyBuilder {
        HttpPolicyBuilder::new(id)
    }

    pub fn id(&self) -> &HttpPolicyId {
        &self.id
    }

    pub fn endpoints(&self) -> &[ApprovedEndpoint] {
        &self.endpoints
    }

    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    pub const fn max_request_bytes(&self) -> NonZeroUsize {
        self.max_request_bytes
    }

    pub const fn max_response_bytes(&self) -> NonZeroUsize {
        self.max_response_bytes
    }

    pub const fn retry_after_max(&self) -> Duration {
        self.retry_after_max
    }

    pub const fn retry_after_fallback(&self) -> Duration {
        self.retry_after_fallback
    }

    pub fn idempotency_header(&self) -> &HeaderName {
        &self.idempotency_header
    }

    pub fn attempt_header(&self) -> &HeaderName {
        &self.attempt_header
    }

    pub(crate) fn authorizer(&self) -> &dyn RequestAuthorizer {
        self.authorizer.as_ref()
    }

    pub(crate) fn approves(&self, url: &Url) -> bool {
        is_safe_url(url) && self.endpoints.iter().any(|endpoint| endpoint.matches(url))
    }
}

/// Builder for one immutable, registration-owned HTTP policy.
pub struct HttpPolicyBuilder {
    id: HttpPolicyId,
    endpoints: Vec<ApprovedEndpoint>,
    connect_timeout: Duration,
    request_timeout: Duration,
    max_request_bytes: usize,
    max_response_bytes: usize,
    retry_after_max: Duration,
    retry_after_fallback: Duration,
    idempotency_header: HeaderName,
    attempt_header: HeaderName,
    authorizer: Arc<dyn RequestAuthorizer>,
}

impl fmt::Debug for HttpPolicyBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpPolicyBuilder")
            .field("id", &self.id)
            .field("endpoints", &self.endpoints)
            .field("authorizer", &"[REDACTED]")
            .finish()
    }
}

impl HttpPolicyBuilder {
    pub fn new(id: HttpPolicyId) -> Self {
        Self {
            id,
            endpoints: Vec::new(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_request_bytes: MAX_INLINE_PAYLOAD_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            retry_after_max: DEFAULT_RETRY_AFTER_MAX,
            retry_after_fallback: DEFAULT_RETRY_AFTER_FALLBACK,
            idempotency_header: HeaderName::from_static("idempotency-key"),
            attempt_header: HeaderName::from_static("x-aux-attempt-id"),
            authorizer: Arc::new(NoopAuthorizer),
        }
    }

    pub fn endpoint(mut self, endpoint: ApprovedEndpoint) -> Self {
        self.endpoints.push(endpoint);
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub fn max_request_bytes(mut self, bytes: usize) -> Self {
        self.max_request_bytes = bytes;
        self
    }

    pub fn max_response_bytes(mut self, bytes: usize) -> Self {
        self.max_response_bytes = bytes;
        self
    }

    pub fn retry_after_max(mut self, duration: Duration) -> Self {
        self.retry_after_max = duration;
        self
    }

    pub fn retry_after_fallback(mut self, duration: Duration) -> Self {
        self.retry_after_fallback = duration;
        self
    }

    pub fn idempotency_header(mut self, name: HeaderName) -> Self {
        self.idempotency_header = name;
        self
    }

    pub fn attempt_header(mut self, name: HeaderName) -> Self {
        self.attempt_header = name;
        self
    }

    pub fn authorizer<A: RequestAuthorizer>(mut self, authorizer: A) -> Self {
        self.authorizer = Arc::new(authorizer);
        self
    }

    pub fn try_build(self) -> Result<HttpPolicy, HttpJobError> {
        if self.endpoints.is_empty() {
            return Err(HttpJobError::EndpointNotApproved);
        }
        let (max_request_bytes, max_response_bytes) = validate_limits(&self)?;
        validate_builder_options(&self)?;
        let retry_after_fallback = self.retry_after_fallback.min(self.retry_after_max);
        let connect_timeout = self.connect_timeout.min(self.request_timeout);
        Ok(HttpPolicy {
            id: self.id,
            endpoints: self.endpoints,
            connect_timeout,
            request_timeout: self.request_timeout,
            max_request_bytes,
            max_response_bytes,
            retry_after_max: self.retry_after_max,
            retry_after_fallback,
            idempotency_header: self.idempotency_header,
            attempt_header: self.attempt_header,
            authorizer: self.authorizer,
        })
    }
}

fn validate_limits(
    builder: &HttpPolicyBuilder,
) -> Result<(NonZeroUsize, NonZeroUsize), HttpJobError> {
    let max_request_bytes =
        NonZeroUsize::new(builder.max_request_bytes).ok_or(ValidationError::InvalidValue {
            field: "HTTP request body limit",
        })?;
    let max_response_bytes =
        NonZeroUsize::new(builder.max_response_bytes).ok_or(ValidationError::InvalidValue {
            field: "HTTP response body limit",
        })?;
    if max_request_bytes.get() > MAX_INLINE_PAYLOAD_BYTES {
        return Err(HttpJobError::RequestBodyTooLarge);
    }
    if max_response_bytes.get() > MAX_INLINE_PAYLOAD_BYTES {
        return Err(HttpJobError::ResponseBodyTooLarge);
    }
    Ok((max_request_bytes, max_response_bytes))
}

fn validate_builder_options(builder: &HttpPolicyBuilder) -> Result<(), HttpJobError> {
    validate_timeout("HTTP connect timeout", builder.connect_timeout)?;
    validate_timeout("HTTP request timeout", builder.request_timeout)?;
    validate_timeout("Retry-After maximum", builder.retry_after_max)?;
    validate_timeout("Retry-After fallback", builder.retry_after_fallback)?;
    validate_header(&builder.idempotency_header)?;
    validate_header(&builder.attempt_header)?;
    if builder.idempotency_header == builder.attempt_header {
        return Err(HttpJobError::SensitiveHeader);
    }
    Ok(())
}

fn validate_timeout(field: &'static str, timeout: Duration) -> Result<(), HttpJobError> {
    if timeout.is_zero() {
        return Err(HttpJobError::Validation(ValidationError::InvalidValue {
            field,
        }));
    }
    Ok(())
}

fn validate_header(name: &HeaderName) -> Result<(), HttpJobError> {
    if is_caller_forbidden_header(name) {
        return Err(HttpJobError::SensitiveHeader);
    }
    Ok(())
}
