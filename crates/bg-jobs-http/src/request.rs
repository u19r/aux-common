use std::{
    fmt,
    time::{Duration, Instant},
};

use bg_jobs::{AttemptId, ExecutionId, MAX_INLINE_PAYLOAD_BYTES};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, header};
use http_request::{Url, method_telemetry_label};

use crate::{
    HttpJobError, HttpPolicyId,
    constants::{MAX_HTTP_HEADER_BYTES, MAX_HTTP_HEADER_COUNT},
};

/// Bounded metadata exposed for request diagnostics.
///
/// This projection contains sizes only. It never contains the request URL,
/// header names or values, body contents, or credentials.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HttpRequestDiagnostic {
    /// Number of request headers in the bounded diagnostic projection.
    pub header_count: usize,
    /// Number of request-body bytes in the bounded diagnostic projection.
    pub body_bytes: usize,
}

impl fmt::Debug for HttpRequestDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRequestDiagnostic")
            .field("header_count", &self.header_count)
            .field("body_bytes", &self.body_bytes)
            .finish()
    }
}

/// Input for constructing one immutable outbound HTTP request.
#[derive(Clone)]
pub struct HttpRequestInput {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl fmt::Debug for HttpRequestInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRequestInput")
            .field("method", &method_telemetry_label(&self.method))
            .field("url", &"[REDACTED]")
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// A request payload that contains no credential or secret-header material.
#[derive(Clone)]
pub struct HttpRequest {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Bytes,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRequest")
            .field("method", &method_telemetry_label(&self.method))
            .field("url", &"[REDACTED]")
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl HttpRequest {
    pub fn try_new(input: HttpRequestInput) -> Result<Self, HttpJobError> {
        if input.body.len() > MAX_INLINE_PAYLOAD_BYTES {
            return Err(HttpJobError::RequestBodyTooLarge);
        }
        validate_url(&input.url)?;
        validate_headers(&input.headers, HeaderValidation::Caller)?;
        Ok(Self {
            method: input.method,
            url: input.url,
            headers: input.headers,
            body: input.body,
        })
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn body_bytes(&self) -> usize {
        self.body.len()
    }

    /// Returns bounded request metadata for diagnostics.
    ///
    /// Secret-bearing projections are rejected at this library boundary. A
    /// successful projection contains only header and body lengths.
    pub fn diagnostic_projection(
        &self,
        include_secret: bool,
    ) -> Result<HttpRequestDiagnostic, HttpJobError> {
        if include_secret {
            return Err(HttpJobError::SensitiveProjection);
        }
        Ok(HttpRequestDiagnostic {
            header_count: self.headers.len(),
            body_bytes: self.body.len(),
        })
    }

    pub(crate) fn body_for_transport(&self) -> Bytes {
        self.body.clone()
    }
}

/// Stable and per-attempt identity supplied by the job engine.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HttpAttempt {
    pub execution_id: ExecutionId,
    pub attempt_id: AttemptId,
    pub deadline: Option<Instant>,
}

impl fmt::Debug for HttpAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpAttempt")
            .field("execution_id", &"[REDACTED]")
            .field("attempt_id", &"[REDACTED]")
            .field("deadline", &self.deadline)
            .finish()
    }
}

impl HttpAttempt {
    pub const fn new(
        execution_id: ExecutionId,
        attempt_id: AttemptId,
        deadline: Option<Instant>,
    ) -> Self {
        Self {
            execution_id,
            attempt_id,
            deadline,
        }
    }

    pub fn remaining(self, now: Instant) -> Option<Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(now))
    }
}

/// A policy-bound HTTP job. The request itself is opaque to the durable core;
/// credentials and authorizer state live only in the executor registration.
#[derive(Clone, Debug)]
pub struct HttpJob {
    /// Identifier of the executor policy selected for this request.
    pub policy: HttpPolicyId,
    /// Validated request payload sent through the selected policy.
    pub request: HttpRequest,
}

impl HttpJob {
    pub fn new(policy: HttpPolicyId, request: HttpRequest) -> Self {
        Self { policy, request }
    }
}

fn validate_url(url: &Url) -> Result<(), HttpJobError> {
    if url.scheme() != "https" {
        return Err(HttpJobError::InsecureEndpoint);
    }
    if !is_safe_url(url) {
        return Err(HttpJobError::EndpointNotApproved);
    }
    Ok(())
}

pub(crate) fn is_safe_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && !url
            .host()
            .is_some_and(|host| matches!(host, url::Host::Ipv4(_) | url::Host::Ipv6(_)))
}

pub(crate) enum HeaderValidation<'a> {
    Caller,
    Authorized {
        url: &'a Url,
        identity_headers: [&'a HeaderName; 2],
        original_identity_values: [Option<&'a HeaderValue>; 2],
    },
}

pub(crate) fn has_header_value(headers: &HeaderMap, name: &HeaderName) -> bool {
    headers.get_all(name).iter().next().is_some()
}

pub(crate) fn validate_headers(
    headers: &HeaderMap,
    validation: HeaderValidation<'_>,
) -> Result<(), HttpJobError> {
    match validation {
        HeaderValidation::Caller => {
            if headers.keys().any(is_caller_forbidden_header) {
                return Err(HttpJobError::SensitiveHeader);
            }
        }
        HeaderValidation::Authorized {
            url,
            identity_headers,
            original_identity_values,
        } => {
            if identity_headers.iter().enumerate().any(|(index, name)| {
                has_duplicate_header(headers, name)
                    || headers.get(*name) != original_identity_values[index]
            }) {
                return Err(HttpJobError::SensitiveHeader);
            }
            if headers.keys().any(is_forbidden_authorized_header)
                || authorizer_headers_are_duplicated(headers)
            {
                return Err(HttpJobError::SensitiveHeader);
            }
            if headers
                .get(header::HOST)
                .is_some_and(|value| !host_header_matches(value, url))
            {
                return Err(HttpJobError::SensitiveHeader);
            }
        }
    }
    validate_header_limits(headers)
}

pub(crate) fn validate_header_limits(headers: &HeaderMap) -> Result<(), HttpJobError> {
    if headers.len() > MAX_HTTP_HEADER_COUNT {
        return Err(HttpJobError::HeaderCountTooLarge);
    }

    let mut byte_count = 0usize;
    for (name, value) in headers {
        byte_count = byte_count
            .checked_add(name.as_str().len())
            .and_then(|count| count.checked_add(value.as_bytes().len()))
            .ok_or(HttpJobError::HeaderBytesTooLarge)?;
    }
    if byte_count > MAX_HTTP_HEADER_BYTES {
        return Err(HttpJobError::HeaderBytesTooLarge);
    }
    Ok(())
}

pub(crate) fn is_caller_forbidden_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization"
            | "cookie"
            | "host"
            | "proxy-authorization"
            | "set-cookie"
            | "x-api-key"
            | "x-amz-security-token"
            | "x-amz-date"
            | "x-amz-content-sha256"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "forwarded"
            | "via"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-forwarded-port"
            | "x-forwarded-prefix"
            | "x-real-ip"
            | "x-client-ip"
            | "cf-connecting-ip"
            | "true-client-ip"
            | "fastly-client-ip"
            | "x-original-url"
            | "x-rewrite-url"
            | "x-original-host"
            | "x-unencoded-url"
            | "x-http-method-override"
            | "x-http-method"
            | "x-method-override"
            | "x-amzn-trace-id"
            | "referer"
            | "origin"
    )
}

fn is_forbidden_authorized_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "cookie"
            | "set-cookie"
            | "x-api-key"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "forwarded"
            | "via"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-forwarded-port"
            | "x-forwarded-prefix"
            | "x-real-ip"
            | "x-client-ip"
            | "cf-connecting-ip"
            | "true-client-ip"
            | "fastly-client-ip"
            | "x-original-url"
            | "x-rewrite-url"
            | "x-original-host"
            | "x-unencoded-url"
            | "x-http-method-override"
            | "x-http-method"
            | "x-method-override"
            | "x-amzn-trace-id"
            | "referer"
            | "origin"
    )
}

fn authorizer_headers_are_duplicated(headers: &HeaderMap) -> bool {
    [
        header::AUTHORIZATION,
        header::HOST,
        HeaderName::from_static("x-amz-date"),
        HeaderName::from_static("x-amz-content-sha256"),
        HeaderName::from_static("x-amz-security-token"),
    ]
    .iter()
    .any(|name| has_duplicate_header(headers, name))
}

fn has_duplicate_header(headers: &HeaderMap, name: &HeaderName) -> bool {
    let mut values = headers.get_all(name).iter();
    values.next().is_some() && values.next().is_some()
}

fn host_header_matches(value: &HeaderValue, url: &Url) -> bool {
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let Some(port) = url.port() else {
        return value.eq_ignore_ascii_case(host);
    };
    let value_bytes = value.as_bytes();
    let host_bytes = host.as_bytes();
    let Some(port_bytes) = value_bytes.get(host_bytes.len().saturating_add(1)..) else {
        return false;
    };
    value_bytes.len() == host_bytes.len().saturating_add(1 + port_bytes.len())
        && value_bytes.get(host_bytes.len()) == Some(&b':')
        && value_bytes[..host_bytes.len()].eq_ignore_ascii_case(host_bytes)
        && parse_host_port(port_bytes) == Some(port)
}

fn parse_host_port(value: &[u8]) -> Option<u16> {
    if value.is_empty() {
        return None;
    }
    let mut port = 0u16;
    for digit in value {
        let digit = *digit;
        if !digit.is_ascii_digit() {
            return None;
        }
        port = port.checked_mul(10)?.checked_add(u16::from(digit - b'0'))?;
    }
    Some(port)
}

pub(crate) fn identifier_header_value(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    value
}
