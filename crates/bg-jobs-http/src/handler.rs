use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use http::{HeaderMap, HeaderValue, header};
use http_request::{
    AllowedDomain, HttpClient, HttpResponse, RetryConfig, TenantHttpClient, Transport,
};

use crate::{
    ApprovedEndpoint, AuthorizationRequest, HttpAttempt, HttpClassification, HttpJob, HttpJobError,
    HttpPolicy, HttpPolicyId,
    classifier::classify_response_body_error,
    classify_response, classify_transport,
    request::{HeaderValidation, has_header_value, identifier_header_value, validate_headers},
    transport::{BoundClient, BoundPolicy, PolicyBoundTransport, SharedTransport},
};

/// Shared, immutable HTTP clients and a trusted policy registry.
pub struct HttpExecutor {
    policies: BTreeMap<HttpPolicyId, BoundPolicy>,
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl fmt::Debug for HttpExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpExecutor")
            .field("policies", &self.policies.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl HttpExecutor {
    pub fn builder() -> HttpExecutorBuilder {
        HttpExecutorBuilder::default()
    }

    pub fn try_new(policies: impl IntoIterator<Item = HttpPolicy>) -> Result<Self, HttpJobError> {
        let mut builder = Self::builder();
        for policy in policies {
            builder = builder.policy(policy);
        }
        builder.try_build()
    }

    pub fn policy(&self, id: &HttpPolicyId) -> Option<&HttpPolicy> {
        self.policies.get(id).map(|bound| &bound.policy)
    }

    pub async fn execute(
        &self,
        job: &HttpJob,
        attempt: HttpAttempt,
    ) -> Result<HttpClassification, HttpJobError> {
        let bound = self
            .policies
            .get(&job.policy)
            .ok_or(HttpJobError::UnknownPolicy)?;
        let policy = &bound.policy;
        validate_request(policy, job)?;
        // Reject an expired attempt before invoking an execution-time
        // authorizer.  Credential providers may perform I/O; an attempt that
        // cannot send must not resolve credentials or invoke signing first.
        let deadline = ExecutionDeadline::new(policy, attempt, Arc::clone(&self.clock))?;
        let signed_headers = deadline
            .run(authorize_request(policy, job, attempt))
            .await??;
        let timeout = deadline.remaining()?;
        let response =
            match tokio::time::timeout(timeout, send_request(bound, job, signed_headers, timeout))
                .await
            {
                Ok(response) => response,
                Err(_) => Err(RequestSendError::Transport(
                    http_request::HttpRequestError::Transport {
                        kind: http_request::HttpRequestErrorKind::Timeout,
                    },
                )),
            };
        let response = match response {
            Ok(response) => response.with_max_body_size(Some(policy.max_response_bytes().get())),
            Err(RequestSendError::Build) => return Err(HttpJobError::RequestBuild),
            Err(RequestSendError::Transport(error)) => {
                let classification =
                    classify_transport(error.kind(), policy.retry_after_fallback());
                return Ok(classification);
            }
        };
        let remaining = deadline.remaining()?;
        let classification =
            match tokio::time::timeout(remaining, classify_response_body(response, policy)).await {
                Ok(classification) => classification,
                Err(_) => classify_transport(
                    http_request::HttpRequestErrorKind::Timeout,
                    policy.retry_after_fallback(),
                ),
            };
        Ok(classification)
    }
}

async fn authorize_request(
    policy: &HttpPolicy,
    job: &HttpJob,
    attempt: HttpAttempt,
) -> Result<HeaderMap, HttpJobError> {
    let mut headers = job.request.headers().clone();
    insert_identity_headers(&mut headers, policy, attempt)?;
    let original_idempotency = headers.get(policy.idempotency_header()).cloned();
    let original_attempt = headers.get(policy.attempt_header()).cloned();
    let request = AuthorizationRequest::new(
        job.request.method(),
        job.request.url(),
        headers,
        job.request.body(),
    );
    let signed_headers = policy
        .authorizer()
        .authorize(request)
        .await
        .map_err(HttpJobError::Authorization)?;
    validate_headers(
        &signed_headers,
        HeaderValidation::Authorized {
            url: job.request.url(),
            identity_headers: [policy.idempotency_header(), policy.attempt_header()],
            original_identity_values: [original_idempotency.as_ref(), original_attempt.as_ref()],
        },
    )?;
    Ok(signed_headers)
}

async fn send_request(
    bound: &BoundPolicy,
    job: &HttpJob,
    headers: HeaderMap,
    timeout: Duration,
) -> Result<HttpResponse, RequestSendError> {
    let method = job.request.method().clone();
    let url = job.request.url().clone();
    let body = job.request.body_for_transport();
    match &bound.client {
        BoundClient::Restricted(client) => client
            .request(method, url)
            .headers(remove_signing_host(headers))
            .body(body)
            .timeout(timeout)
            .send()
            .await
            .map_err(RequestSendError::Transport),
        BoundClient::Custom(client) => {
            let request = client
                .request(method, url)
                .headers(headers)
                .body(body)
                .timeout(timeout)
                .build()
                .map_err(|_| RequestSendError::Build)?;
            client
                .execute(request)
                .await
                .map_err(RequestSendError::Transport)
        }
    }
}

async fn classify_response_body(response: HttpResponse, policy: &HttpPolicy) -> HttpClassification {
    let now = SystemTime::now();
    let preliminary = classify_response(
        &response,
        policy.max_response_bytes().get(),
        policy.retry_after_max(),
        policy.retry_after_fallback(),
        now,
    );
    if preliminary.code() == "http_response_too_large" {
        return preliminary;
    }
    let status = response.status();
    match response.bytes().await {
        Ok(_) => preliminary,
        Err(error) => {
            classify_response_body_error(status, error.kind(), policy.retry_after_fallback())
        }
    }
}

/// Builder for a shared HTTP executor. Building compiles policy-bound clients;
/// jobs do not construct clients or choose transport retry policy.
#[derive(Default)]
pub struct HttpExecutorBuilder {
    policies: Vec<HttpPolicy>,
    transport: Option<SharedTransport>,
    clock: Option<Arc<dyn Fn() -> Instant + Send + Sync>>,
}

impl fmt::Debug for HttpExecutorBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpExecutorBuilder")
            .field("policy_count", &self.policies.len())
            .field("transport_configured", &self.transport.is_some())
            .finish()
    }
}

impl HttpExecutorBuilder {
    pub fn policy(mut self, policy: HttpPolicy) -> Self {
        self.policies.push(policy);
        self
    }

    pub fn with_transport<T: PolicyBoundTransport + 'static>(mut self, transport: T) -> Self {
        self.transport = Some(SharedTransport(Arc::new(transport)));
        self
    }

    #[cfg(test)]
    pub(crate) fn test_clock(
        mut self,
        clock: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Self {
        self.clock = Some(Arc::new(clock));
        self
    }

    pub fn try_build(self) -> Result<HttpExecutor, HttpJobError> {
        if self.policies.is_empty() {
            return Err(HttpJobError::NoPolicies);
        }
        let policies = bind_policies(self.policies, self.transport)?;
        Ok(HttpExecutor {
            policies,
            clock: self.clock.unwrap_or_else(|| Arc::new(Instant::now)),
        })
    }
}

fn bind_policies(
    policies: Vec<HttpPolicy>,
    transport: Option<SharedTransport>,
) -> Result<BTreeMap<HttpPolicyId, BoundPolicy>, HttpJobError> {
    if transport.as_ref().is_some_and(|transport| {
        !transport.redirects_disabled()
            || !transport.destination_policy_enforced()
            || !transport.deadline_enforced()
    }) {
        return Err(HttpJobError::RequestBuild);
    }
    let mut bound = BTreeMap::new();
    for policy in policies {
        let id = policy.id().clone();
        if bound.contains_key(&id) {
            return Err(HttpJobError::DuplicatePolicy);
        }
        let client = match transport.as_ref() {
            Some(transport) => BoundClient::Custom(build_custom_client(&policy, transport)?),
            None => BoundClient::Restricted(build_restricted_client(&policy)?),
        };
        bound.insert(id, BoundPolicy { policy, client });
    }
    Ok(bound)
}

fn build_custom_client(
    policy: &HttpPolicy,
    transport: &SharedTransport,
) -> Result<HttpClient, HttpJobError> {
    HttpClient::builder()
        .retry(no_retry_config())
        .with_reqwest_builder(|builder| {
            builder
                .connect_timeout(policy.connect_timeout())
                .timeout(policy.request_timeout())
                .redirect(http_request::reqwest::redirect::Policy::none())
        })
        .with_transport(transport.clone())
        .build()
        .map_err(|_| HttpJobError::RequestBuild)
}

enum RequestSendError {
    Build,
    Transport(http_request::HttpRequestError),
}

struct ExecutionDeadline {
    deadline: Instant,
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl ExecutionDeadline {
    fn new(
        policy: &HttpPolicy,
        attempt: HttpAttempt,
        clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    ) -> Result<Self, HttpJobError> {
        let now = clock();
        let policy_deadline = now
            .checked_add(policy.request_timeout())
            .ok_or(HttpJobError::InvalidDeadline)?;
        let deadline = attempt
            .deadline
            .map_or(policy_deadline, |attempt_deadline| {
                attempt_deadline.min(policy_deadline)
            });
        if deadline <= now {
            return Err(HttpJobError::InvalidDeadline);
        }
        Ok(Self { deadline, clock })
    }

    fn remaining(&self) -> Result<Duration, HttpJobError> {
        let remaining = self.deadline.saturating_duration_since((self.clock)());
        if remaining.is_zero() {
            return Err(HttpJobError::InvalidDeadline);
        }
        Ok(remaining)
    }

    async fn run<F: Future>(&self, future: F) -> Result<F::Output, HttpJobError> {
        let remaining = self.remaining()?;
        tokio::time::timeout(remaining, future)
            .await
            .map_err(|_| HttpJobError::InvalidDeadline)
    }
}

fn build_restricted_client(policy: &HttpPolicy) -> Result<TenantHttpClient, HttpJobError> {
    let domains = policy
        .endpoints()
        .iter()
        .map(|endpoint| {
            if endpoint.allows_subdomains() {
                AllowedDomain::with_subdomains(endpoint.host())
            } else {
                AllowedDomain::exact(endpoint.host())
            }
        })
        .collect::<Vec<_>>();
    let ports = policy
        .endpoints()
        .iter()
        .map(ApprovedEndpoint::port)
        .collect::<Vec<_>>();
    TenantHttpClient::builder("bg-jobs-http")
        .allowlist(domains)
        .allowed_ports(ports)
        .max_content_length(policy.max_request_bytes().get())
        .max_response_length(policy.max_response_bytes().get())
        .connect_timeout(policy.connect_timeout())
        .timeout(policy.request_timeout())
        .max_redirects(0)
        .retry(no_retry_config())
        .build()
        .map_err(|_| HttpJobError::RequestBuild)
}

fn no_retry_config() -> RetryConfig {
    RetryConfig {
        max_retries: 0,
        base_delay: Duration::ZERO,
        max_delay: Duration::ZERO,
        retry_non_idempotent: false,
    }
}

fn validate_request(policy: &HttpPolicy, job: &HttpJob) -> Result<(), HttpJobError> {
    if job.request.body_bytes() > policy.max_request_bytes().get() {
        return Err(HttpJobError::RequestBodyTooLarge);
    }
    if !policy.approves(job.request.url()) {
        return Err(HttpJobError::EndpointNotApproved);
    }
    Ok(())
}

fn insert_identity_headers(
    headers: &mut HeaderMap,
    policy: &HttpPolicy,
    attempt: HttpAttempt,
) -> Result<(), HttpJobError> {
    if has_header_value(headers, policy.idempotency_header())
        || has_header_value(headers, policy.attempt_header())
    {
        return Err(HttpJobError::SensitiveHeader);
    }
    let execution =
        HeaderValue::from_str(&identifier_header_value(attempt.execution_id.as_bytes()))
            .map_err(|_| HttpJobError::RequestBuild)?;
    let attempt_id = HeaderValue::from_str(&identifier_header_value(attempt.attempt_id.as_bytes()))
        .map_err(|_| HttpJobError::RequestBuild)?;
    headers.insert(policy.idempotency_header().clone(), execution);
    headers.insert(policy.attempt_header().clone(), attempt_id);
    Ok(())
}

fn remove_signing_host(mut headers: HeaderMap) -> HeaderMap {
    headers.remove(header::HOST);
    headers
}
