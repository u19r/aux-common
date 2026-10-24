use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    marker::PhantomData,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use bg_jobs::{AttemptId, ExecutionId, JobOutcome, MAX_INLINE_PAYLOAD_BYTES, Timestamp};
use bg_jobs_http::{
    ApprovedEndpoint, AuthorizationErrorKind, AuthorizationFuture, AuthorizationRequest,
    BatchClassificationLimits, BatchItemContext, BatchResponse, BatchResultSet, HttpAttempt,
    HttpExecutor, HttpJob, HttpJobError, HttpPolicy, HttpPolicyId, HttpRequest,
    HttpRequestDiagnostic, HttpRequestInput, HttpResultClass, PolicyBoundTransport,
    RequestAuthorizer,
};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header::RETRY_AFTER};
use http_request::{
    HttpRequestError, HttpRequestErrorKind, HttpResponse, Transport, TransportFuture, Url,
};
use quint_connect::{Driver, Result, State, Step};
use serde::Deserialize;

use super::{
    constants::{MAX_ATTEMPTS, MAX_RETRY_AFTER_TICKS, RETRY_AFTER_FALLBACK_TICKS},
    model::{
        AuthResult, AuthorityInput, BatchResult, Command, CommandResult, HttpOutcome, HttpStatus,
        Item, JobId, LastTransition, Meta, Node, OperationId, RequestDiagnostic, ResultClass,
        RetryOwner, StateProjection, TransportResult,
    },
};

/// Connector-specific authorizer construction and proof hooks for the shared
/// HTTP/AWS Quint harness.
pub trait ConnectorConfig: Sized + 'static {
    /// Authorizer installed in the production executor.
    type Authorizer: RequestAuthorizer;

    /// Returns the immutable policy identifier used by this connector.
    fn policy_id() -> &'static str;

    /// Builds the concrete authorizer/provider path represented by one model
    /// outcome. Every connector must own this mapping so a model failure class
    /// cannot silently fall back to a successful authorizer.
    fn new_authorizer_for(auth: AuthResult) -> Result<Self::Authorizer>;

    /// Declares which model outcomes have connector-owned authorizer paths.
    /// Unsupported policy outcomes use the shared policy boundary instead of
    /// being synthesized by the connector.
    fn supports_auth_result(_auth: AuthResult) -> bool {
        true
    }

    /// Verifies connector-specific output while keeping secrets out of the
    /// model projection.
    fn assert_authorized(original: &HeaderMap, authorized: &HeaderMap) -> Result;

    /// Verifies the public request diagnostic projection. The HTTP library has
    /// no durable codec; this hook must therefore inspect only the bounded
    /// production projection and must not manufacture a persistence claim.
    fn assert_request_projection(
        projection: &HttpRequestDiagnostic,
        contains_secret: bool,
    ) -> Result;

    /// Names the connector in harness errors.
    fn label() -> &'static str;
}

/// Test-support observation for making the production authorizer boundary
/// observable without putting credentials or provider errors in the model.
#[derive(Clone, Debug)]
struct AuthorizerObservation {
    calls: Arc<AtomicUsize>,
}

impl AuthorizerObservation {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

struct ObservedAuthorizer<A> {
    inner: A,
    observation: AuthorizerObservation,
}

impl<A> ObservedAuthorizer<A> {
    fn new(inner: A, observation: AuthorizerObservation) -> Self {
        Self { inner, observation }
    }
}

impl<A: RequestAuthorizer> RequestAuthorizer for ObservedAuthorizer<A> {
    fn authorize<'a>(&'a self, request: AuthorizationRequest<'a>) -> AuthorizationFuture<'a> {
        self.observation.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.authorize(request)
    }
}

enum ConnectorAuthorizer<A> {
    Concrete(A),
    PolicyDenied,
}

impl<A: RequestAuthorizer> RequestAuthorizer for ConnectorAuthorizer<A> {
    fn authorize<'a>(&'a self, request: AuthorizationRequest<'a>) -> AuthorizationFuture<'a> {
        match self {
            Self::Concrete(authorizer) => authorizer.authorize(request),
            Self::PolicyDenied => Box::pin(async { Err(AuthorizationErrorKind::InvalidRequest) }),
        }
    }
}

fn expected_authorization_error(outcome: AuthResult) -> AuthorizationErrorKind {
    match outcome {
        AuthResult::Authorised => AuthorizationErrorKind::InvalidRequest,
        AuthResult::Denied => AuthorizationErrorKind::InvalidRequest,
        AuthResult::MissingSecret => AuthorizationErrorKind::CredentialUnavailable,
        AuthResult::SignFailure => AuthorizationErrorKind::SigningFailed,
    }
}

/// The connector's transport is deliberately scripted and local. It records
/// that a request crossed the executor boundary and returns only the bounded
/// response/error selected by the model command. Request headers are captured
/// transiently for connector-specific authorization assertions; bodies are
/// never retained.
#[derive(Clone, Debug)]
struct ScriptedTransport {
    inner: Arc<ScriptedTransportState>,
}

struct ScriptedTransportState {
    responses: Mutex<VecDeque<std::result::Result<HttpResponse, HttpRequestError>>>,
    headers: Mutex<Option<HeaderMap>>,
    sent: AtomicUsize,
}

impl std::fmt::Debug for ScriptedTransportState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScriptedTransportState")
            .field("sent", &self.sent.load(Ordering::Relaxed))
            .finish()
    }
}

impl ScriptedTransport {
    fn new() -> Self {
        Self {
            inner: Arc::new(ScriptedTransportState {
                responses: Mutex::new(VecDeque::new()),
                headers: Mutex::new(None),
                sent: AtomicUsize::new(0),
            }),
        }
    }

    fn push(&self, response: std::result::Result<HttpResponse, HttpRequestError>) -> Result {
        self.inner
            .responses
            .lock()
            .map_err(|_| std::io::Error::other("scripted transport response lock poisoned"))?
            .push_back(response);
        Ok(())
    }

    fn sent(&self) -> usize {
        self.inner.sent.load(Ordering::Relaxed)
    }

    fn take_headers(&self) -> Result<HeaderMap> {
        self.inner
            .headers
            .lock()
            .map_err(|_| std::io::Error::other("scripted transport header lock poisoned"))?
            .take()
            .ok_or_else(|| std::io::Error::other("scripted transport captured no headers").into())
    }
}

impl Transport for ScriptedTransport {
    fn send(&self, request: http_request::reqwest::Request) -> TransportFuture {
        self.inner.sent.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut headers) = self.inner.headers.lock() {
            *headers = Some(request.headers().clone());
        }
        let response = self
            .inner
            .responses
            .lock()
            .ok()
            .and_then(|mut responses| responses.pop_front())
            .unwrap_or_else(|| {
                Err(HttpRequestError::Transport {
                    kind: HttpRequestErrorKind::Unknown,
                })
            });
        Box::pin(async move { response })
    }

    fn redirects_disabled(&self) -> bool {
        true
    }

    fn destination_policy_enforced(&self) -> bool {
        true
    }

    fn deadline_enforced(&self) -> bool {
        true
    }
}

impl PolicyBoundTransport for ScriptedTransport {}

/// Full-state connector. `jobs` and batch fields are caller-owned
/// lifecycle context; request validation, authorisation, transport, deadline
/// handling, classification, and batch omission handling run through the
/// public production APIs. The projection is only the typed state receipt
/// consumed by Quint Connect.
#[derive(Debug)]
pub struct ConnectorDriver<C: ConnectorConfig> {
    executor: HttpExecutor,
    transport: ScriptedTransport,
    authorizer: AuthorizerObservation,
    projection_checks: usize,
    jobs: BTreeMap<JobId, HttpJob>,
    projection: StateProjection,
    marker: PhantomData<fn() -> C>,
}

impl<C: ConnectorConfig> State<ConnectorDriver<C>> for StateProjection {
    fn from_driver(driver: &ConnectorDriver<C>) -> Result<Self> {
        Ok(driver.projection.clone())
    }
}

impl<C: ConnectorConfig> Default for ConnectorDriver<C> {
    fn default() -> Self {
        Self::try_default().unwrap_or_else(|error| panic!("connector setup: {error}"))
    }
}

impl<C: ConnectorConfig> ConnectorDriver<C> {
    fn try_default() -> Result<Self> {
        let policy_id = HttpPolicyId::try_new(C::policy_id())?;
        let transport = ScriptedTransport::new();
        let authorizer = AuthorizerObservation::new();
        let executor = Self::build_executor(
            &policy_id,
            transport.clone(),
            Self::authorizer_for(AuthResult::Authorised)?,
            authorizer.clone(),
        )?;
        let jobs = make_jobs(&policy_id, true, 0)?;
        let command = Command::HttpPrepare {
            members: BTreeSet::new(),
        };
        let transition = initial_transition(command.clone());
        let result = CommandResult::HttpApplied {
            transition: transition.clone(),
            result: BatchResult::ItemMissing,
            owner: RetryOwner::NoRetry,
            retry_after: 0,
        };
        Ok(Self {
            executor,
            transport,
            authorizer,
            projection_checks: 0,
            jobs,
            marker: PhantomData,
            projection: StateProjection {
                items: initial_items(),
                meta: initial_meta(),
                command,
                transition,
                result,
            },
        })
    }

    pub fn apply_command_for_test(&mut self, command: Command) -> Result {
        self.apply_command(command)
    }

    pub fn authorization_calls_for_test(&self) -> usize {
        self.authorizer.calls()
    }

    pub fn projection_checks_for_test(&self) -> usize {
        self.projection_checks
    }

    pub fn projection_for_test(&self) -> &StateProjection {
        &self.projection
    }

    fn build_executor(
        policy_id: &HttpPolicyId,
        transport: ScriptedTransport,
        authorizer: ConnectorAuthorizer<C::Authorizer>,
        observation: AuthorizerObservation,
    ) -> Result<HttpExecutor> {
        let policy = HttpPolicy::builder(policy_id.clone())
            .endpoint(ApprovedEndpoint::exact("api.example.com")?)
            .authorizer(ObservedAuthorizer::new(authorizer, observation))
            .request_timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(1))
            .retry_after_max(Duration::from_secs(MAX_RETRY_AFTER_TICKS as u64))
            .retry_after_fallback(Duration::from_secs(RETRY_AFTER_FALLBACK_TICKS as u64))
            .try_build()?;
        Ok(HttpExecutor::builder()
            .policy(policy)
            .with_transport(transport)
            .try_build()?)
    }

    fn authorizer_for(auth: AuthResult) -> Result<ConnectorAuthorizer<C::Authorizer>> {
        if C::supports_auth_result(auth) {
            return Ok(ConnectorAuthorizer::Concrete(C::new_authorizer_for(auth)?));
        }
        if auth == AuthResult::Denied {
            return Ok(ConnectorAuthorizer::PolicyDenied);
        }
        Err(std::io::Error::other(format!(
            "{} connector does not support authorization class {auth:?}",
            C::label()
        ))
        .into())
    }

    /// `mbtDispatchNondet` nests `mbtStep` in an `any` action. Quint Connect
    /// reports the inner action and no command pick. The selected command is
    /// serialized in the next state, so recover its tag and derive the fixed
    /// bounded inputs from the current receipt. Direct `mbtStep` traces carry
    /// a typed command pick and use that exact value.
    fn command_from_step(&self, step: &Step) -> Result<Command> {
        if let Some(value) = step.nondet_picks.get("command") {
            return Ok(Command::deserialize(value.clone())?);
        }
        let rendered = step.to_string();
        let line = rendered
            .lines()
            .find(|line| line.contains("+ lastCommand: "))
            .ok_or_else(|| std::io::Error::other("connector step has no serialized command"))?;
        let command_value = line
            .split_once("+ lastCommand: ")
            .map(|(_, value)| value.trim())
            .ok_or_else(|| std::io::Error::other("connector step command value is missing"))?;
        let name = command_value
            .split(['(', '{'])
            .next()
            .map(str::trim)
            .ok_or_else(|| std::io::Error::other("connector step command tag is missing"))?;
        let job = self.projection.meta.last_item;
        let item = self
            .projection
            .items
            .get(&job)
            .ok_or_else(|| std::io::Error::other("connector command job is absent"))?;
        match name {
            "HttpPrepare" => Ok(Command::HttpPrepare {
                members: BTreeSet::from([JobId::JobA, JobId::JobB]),
            }),
            "HttpInput" => Ok(Command::HttpInput {
                job,
                secret: true,
                body_bytes: MAX_INLINE_PAYLOAD_BYTES as i64,
                destination_valid: true,
            }),
            "HttpAuthorize" => Ok(Command::HttpAuthorize {
                job,
                auth: parse_auth_result(command_value),
            }),
            "HttpProject" => Ok(Command::HttpProject {
                job,
                include_secret: command_value.contains("includeSecret: true")
                    || command_value.contains("include_secret: true"),
            }),
            "HttpExecute" => Ok(Command::HttpExecute {
                authority: authority_input(job, item),
                status: HttpStatus::Status429,
                transport: TransportResult::TransportOk,
                retry_after: MAX_RETRY_AFTER_TICKS,
            }),
            "HttpRetryCommand" => Ok(Command::HttpRetryCommand {
                job,
                owner: RetryOwner::EngineOwnsRetry,
            }),
            "HttpDuplicate" => Ok(Command::HttpDuplicate { job }),
            "HttpOmit" => Ok(Command::HttpOmit { job }),
            other => Err(std::io::Error::other(format!(
                "connector step command tag not implemented: {other}"
            ))
            .into()),
        }
    }

    fn apply_command(&mut self, command: Command) -> Result {
        match command {
            Command::HttpPrepare { members } => self.prepare(members),
            Command::HttpInput {
                job,
                secret,
                body_bytes,
                destination_valid,
            } => self.receive_input(job, secret, body_bytes, destination_valid),
            Command::HttpAuthorize { job, auth } => self.authorize(job, auth),
            Command::HttpProject {
                job,
                include_secret,
            } => self.project(job, include_secret),
            Command::HttpExecute {
                authority,
                status,
                transport,
                retry_after,
            } => self.execute(authority, status, transport, retry_after),
            Command::HttpRetryCommand { job, owner } => self.retry(job, owner),
            Command::HttpDuplicate { job } => self.duplicate(job),
            Command::HttpOmit { job } => self.omit(job),
        }
    }

    fn prepare(&mut self, members: BTreeSet<JobId>) -> Result {
        let allowed = self.projection.meta.batch_members.is_empty();
        if !allowed {
            return Err(std::io::Error::other("model emitted an invalid prepare command").into());
        }
        for (job, item) in &mut self.projection.items {
            item.member = members.contains(job);
            item.attempts = if item.member { 1 } else { 0 };
            item.attempt_executed = false;
            item.result = BatchResult::ItemMissing;
        }
        let results: BTreeMap<JobId, BatchResult> = members
            .iter()
            .copied()
            .map(|job| (job, BatchResult::ItemMissing))
            .collect();
        self.projection.meta.batch_members = members.clone();
        self.projection.meta.batch_results = results.clone();
        self.finish(
            Command::HttpPrepare { members },
            true,
            HttpOutcome::BatchPrepared,
            BatchResult::ItemMissing,
            RetryOwner::NoRetry,
            0,
            results,
        )
    }

    fn receive_input(
        &mut self,
        job: JobId,
        secret: bool,
        body_bytes: i64,
        destination_valid: bool,
    ) -> Result {
        let current = self.item(job)?.clone();
        let eligible = current.member
            && current.result == BatchResult::ItemMissing
            && !current.attempt_executed;
        let valid = eligible
            && body_bytes >= 0
            && body_bytes <= MAX_INLINE_PAYLOAD_BYTES as i64
            && destination_valid;
        let result = if !eligible {
            current.result
        } else if valid {
            BatchResult::ItemMissing
        } else {
            BatchResult::ItemDeadLetter
        };

        if eligible {
            let stored_body_bytes = if body_bytes <= MAX_INLINE_PAYLOAD_BYTES as i64 {
                body_bytes
            } else {
                0
            };
            {
                let item = self.item_mut(job)?;
                item.input_secret = secret;
                item.body_bytes = stored_body_bytes;
                item.invalid_input = !valid;
                item.destination_valid = destination_valid;
                item.idempotency_header = 0;
                item.duplicate = false;
                item.omitted = false;
                item.result = result;
            }

            // A too-large payload must be rejected by the production request
            // constructor. Use only max+1 bytes so a direct typed trace stays
            // bounded even when it supplies a huge integer.
            if valid {
                let policy_id = self.policy_id()?;
                let replacement =
                    make_job(&policy_id, destination_valid, stored_body_bytes, secret)?;
                self.jobs.insert(job, replacement);
            } else if body_bytes > MAX_INLINE_PAYLOAD_BYTES as i64 {
                let oversized =
                    Bytes::from(vec![
                        0_u8;
                        MAX_INLINE_PAYLOAD_BYTES.checked_add(1).ok_or_else(
                            || std::io::Error::other("request body bound overflow")
                        )?
                    ]);
                let request = HttpRequest::try_new(HttpRequestInput {
                    method: Method::POST,
                    url: Url::parse("https://api.example.com/jobs/oversized")?,
                    headers: HeaderMap::new(),
                    body: oversized,
                });
                if !matches!(request, Err(HttpJobError::RequestBodyTooLarge)) {
                    return Err(std::io::Error::other(
                        "oversized request did not cross the production request boundary",
                    )
                    .into());
                }
            }
        }

        self.set_last_item(job);
        let batch_result = self.update_batch_result(job, result);
        self.finish(
            Command::HttpInput {
                job,
                secret,
                body_bytes,
                destination_valid,
            },
            valid,
            if valid {
                HttpOutcome::Initialised
            } else {
                HttpOutcome::InvalidInputRejected
            },
            result,
            current.retry_owner,
            current.retry_after,
            batch_result,
        )
    }

    fn authorize(&mut self, job: JobId, auth: AuthResult) -> Result {
        let current = self.item(job)?.clone();
        let eligible = current.member
            && current.result == BatchResult::ItemMissing
            && !current.attempt_executed;
        let request_ready = eligible
            && current.destination_valid
            && current.body_bytes <= MAX_INLINE_PAYLOAD_BYTES as i64;
        let allowed = request_ready && auth == AuthResult::Authorised;
        let result = if eligible && !allowed {
            BatchResult::ItemDeadLetter
        } else {
            current.result
        };

        if request_ready {
            // Every eligible authorization result crosses the same policy and
            // executor boundary as production. The connector supplies the
            // concrete authorizer/provider for the selected model result.
            let original_headers = self
                .jobs
                .get(&job)
                .ok_or_else(|| std::io::Error::other("missing connector job"))?
                .request
                .headers()
                .clone();
            let before_sent = self.transport.sent();
            let before_authorizations = self.authorizer.calls();
            let policy_id = self.policy_id()?;
            self.executor = Self::build_executor(
                &policy_id,
                self.transport.clone(),
                Self::authorizer_for(auth)?,
                self.authorizer.clone(),
            )?;
            if auth == AuthResult::Authorised {
                self.transport.push(scripted_result(
                    HttpStatus::Status2xx,
                    TransportResult::TransportOk,
                    0,
                )?)?;
            }
            let request = self
                .jobs
                .get(&job)
                .ok_or_else(|| std::io::Error::other("missing connector job"))?;
            let execution = run_async(self.executor.execute(
                request,
                HttpAttempt::new(
                    id_from_model(current.execution_id)?,
                    attempt_id_from_model(current.attempt_id)?,
                    Some(Instant::now() + Duration::from_secs(current.lease_until.max(1) as u64)),
                ),
            ))?;
            if self.authorizer.calls() != before_authorizations + 1 {
                return Err(std::io::Error::other(
                    "executor did not invoke concrete authorizer for authorization",
                )
                .into());
            }
            match (auth, execution) {
                (AuthResult::Authorised, Ok(_)) => {
                    if self.transport.sent() == before_sent {
                        return Err(std::io::Error::other(
                            "executor did not invoke scripted transport for authorization",
                        )
                        .into());
                    }
                    let authorized = self.transport.take_headers()?;
                    C::assert_authorized(&original_headers, &authorized)?;
                }
                (AuthResult::Authorised, Err(error)) => {
                    return Err(std::io::Error::other(format!(
                        "authorised request was rejected by executor: {error}"
                    ))
                    .into());
                }
                (rejected, Err(HttpJobError::Authorization(error)))
                    if error == expected_authorization_error(rejected) =>
                {
                    if self.transport.sent() != before_sent {
                        return Err(std::io::Error::other(
                            "rejected authorization reached the scripted transport",
                        )
                        .into());
                    }
                }
                (rejected, Err(error)) => {
                    return Err(std::io::Error::other(format!(
                        "{rejected:?} authorization returned unexpected executor error: {error}"
                    ))
                    .into());
                }
                (rejected, Ok(_)) => {
                    return Err(std::io::Error::other(format!(
                        "{rejected:?} authorization unexpectedly succeeded"
                    ))
                    .into());
                }
            }
        }
        if eligible {
            let item = self.item_mut(job)?;
            item.auth = auth;
            item.idempotency_header = if allowed { current.execution_id } else { 0 };
            item.result = result;
            item.duplicate = false;
            item.omitted = false;
        }

        self.set_last_item(job);
        let batch_result = self.update_batch_result(job, result);
        self.finish(
            Command::HttpAuthorize { job, auth },
            allowed,
            if allowed {
                HttpOutcome::Initialised
            } else {
                HttpOutcome::AuthorisationRejected
            },
            result,
            current.retry_owner,
            current.retry_after,
            batch_result,
        )
    }

    fn project(&mut self, job: JobId, include_secret: bool) -> Result {
        let current = self.item(job)?.clone();
        let state_allows = current.member
            && current.result == BatchResult::ItemMissing
            && !current.attempt_executed
            && !current.invalid_input
            && current.auth == AuthResult::Authorised
            && current.destination_valid
            && current.body_bytes <= MAX_INLINE_PAYLOAD_BYTES as i64;
        let can_inspect = current.member
            && current.result == BatchResult::ItemMissing
            && !current.attempt_executed
            && !current.invalid_input;
        let projection_allows = if can_inspect {
            let projection = {
                let request = &self
                    .jobs
                    .get(&job)
                    .ok_or_else(|| std::io::Error::other("missing connector job"))?
                    .request;
                if request.body_bytes() != usize::try_from(current.body_bytes)? {
                    return Err(
                        std::io::Error::other("request and model body sizes diverged").into(),
                    );
                }
                request.diagnostic_projection(include_secret)
            };
            self.projection_checks += 1;
            match projection {
                Ok(projection) => {
                    C::assert_request_projection(&projection, current.input_secret)?;
                    self.projection.meta.last_projection = RequestDiagnostic {
                        header_count: i64::try_from(projection.header_count)?,
                        body_bytes: i64::try_from(projection.body_bytes)?,
                        includes_url: false,
                        includes_headers: false,
                        includes_body: false,
                    };
                    true
                }
                Err(HttpJobError::SensitiveProjection) => false,
                Err(error) => {
                    return Err(std::io::Error::other(format!(
                        "request diagnostic projection failed: {error}"
                    ))
                    .into());
                }
            }
        } else {
            false
        };
        let allowed = state_allows && projection_allows;

        self.set_last_item(job);
        let result = if allowed {
            BatchResult::ItemMissing
        } else {
            current.result
        };
        let outcome = if allowed {
            HttpOutcome::Initialised
        } else {
            HttpOutcome::ProjectionRejected
        };
        let batch_result = if allowed {
            self.update_batch_result(job, BatchResult::ItemMissing)
        } else {
            self.projection.meta.batch_results.clone()
        };
        self.finish(
            Command::HttpProject {
                job,
                include_secret,
            },
            allowed,
            outcome,
            result,
            current.retry_owner,
            current.retry_after,
            batch_result,
        )
    }

    fn execute(
        &mut self,
        authority: AuthorityInput,
        status: HttpStatus,
        transport: TransportResult,
        requested_retry_after: i64,
    ) -> Result {
        let current = self.item(authority.job)?.clone();
        let valid = authority_matches(&current, &authority);
        if !valid {
            self.set_last_item(authority.job);
            return self.finish(
                Command::HttpExecute {
                    authority,
                    status,
                    transport,
                    retry_after: requested_retry_after,
                },
                false,
                HttpOutcome::InvalidInputRejected,
                current.result,
                current.retry_owner,
                current.retry_after,
                self.projection.meta.batch_results.clone(),
            );
        }

        let original_headers = self
            .jobs
            .get(&authority.job)
            .ok_or_else(|| std::io::Error::other("missing connector job"))?
            .request
            .headers()
            .clone();
        let before_authorizations = self.authorizer.calls();
        let before_sent = self.transport.sent();
        self.transport
            .push(scripted_result(status, transport, requested_retry_after)?)?;
        let job = self
            .jobs
            .get(&authority.job)
            .ok_or_else(|| std::io::Error::other("missing connector job"))?;
        let execution = run_async(self.executor.execute(
            job,
            HttpAttempt::new(
                id_from_model(current.execution_id)?,
                attempt_id_from_model(current.attempt_id)?,
                Some(Instant::now() + Duration::from_secs(current.lease_until.max(1) as u64)),
            ),
        ))??;
        if self.authorizer.calls() != before_authorizations + 1 {
            return Err(std::io::Error::other(
                "executor did not invoke concrete authorizer for execution",
            )
            .into());
        }
        if self.transport.sent() == before_sent {
            return Err(std::io::Error::other("executor did not invoke scripted transport").into());
        }
        let authorized = self.transport.take_headers()?;
        C::assert_authorized(&original_headers, &authorized)?;

        let classification = execution;
        let classified_retry = classification.class() == HttpResultClass::Retry;
        let retry = classified_retry && current.attempts < MAX_ATTEMPTS;
        let success = classification.class() == HttpResultClass::Complete;
        let result = if retry {
            BatchResult::ItemRetry
        } else if success && transport == TransportResult::TransportOk {
            BatchResult::ItemSuccess
        } else {
            BatchResult::ItemDeadLetter
        };
        let outcome =
            if retry && transport == TransportResult::TransportOk && requested_retry_after != 0 {
                HttpOutcome::RetryAfterObserved
            } else if retry {
                HttpOutcome::HttpRetry
            } else if result == BatchResult::ItemSuccess {
                HttpOutcome::HttpSuccess
            } else {
                HttpOutcome::HttpDeadLetter
            };
        let owner = if retry {
            RetryOwner::EngineOwnsRetry
        } else {
            RetryOwner::NoRetry
        };
        let retry_after = clamp_retry_after(requested_retry_after);
        let item = self.item_mut(authority.job)?;
        item.status = status;
        item.transport = transport;
        item.retry_after = retry_after;
        item.retry_owner = owner;
        item.result = result;
        item.outcome_present = true;
        item.attempt_executed = true;
        item.outcome_job = authority.job;
        item.outcome_attempt_id = item.attempt_id;
        item.outcome_revision = item.revision;
        item.outcome_generation = item.generation;
        item.outcome_fence = item.fence;
        item.outcome_token = item.token;
        item.outcome_lease_until = item.lease_until;
        item.outcome_operation = item.operation;
        item.duplicate = false;
        item.omitted = false;
        self.set_last_item(authority.job);
        let batch_result = self.update_batch_result(authority.job, result);
        self.finish(
            Command::HttpExecute {
                authority,
                status,
                transport,
                retry_after: requested_retry_after,
            },
            true,
            outcome,
            result,
            owner,
            retry_after,
            batch_result,
        )
    }

    fn retry(&mut self, job: JobId, owner: RetryOwner) -> Result {
        let current = self.item(job)?.clone();
        let allowed = owner == current.retry_owner
            && current.member
            && current.retry_owner == RetryOwner::EngineOwnsRetry
            && current.attempts < MAX_ATTEMPTS;
        if allowed {
            let item = self.item_mut(job)?;
            item.result = BatchResult::ItemMissing;
            item.attempts += 1;
            item.attempt_id += 1;
            item.outcome_present = false;
            item.attempt_executed = false;
            item.idempotency_header = 0;
            item.retry_owner = RetryOwner::NoRetry;
            item.duplicate = false;
            item.omitted = false;
        }
        self.set_last_item(job);
        let result = if allowed {
            BatchResult::ItemMissing
        } else {
            current.result
        };
        let batch_result = self.update_batch_result(job, result);
        if allowed {
            self.projection.meta.engine_retries += 1;
        }
        self.finish(
            Command::HttpRetryCommand { job, owner },
            allowed,
            if allowed {
                HttpOutcome::HttpRetry
            } else {
                HttpOutcome::ProjectionRejected
            },
            result,
            if allowed {
                RetryOwner::NoRetry
            } else {
                current.retry_owner
            },
            current.retry_after,
            batch_result,
        )
    }

    fn duplicate(&mut self, job: JobId) -> Result {
        let current = self.item(job)?.clone();
        let allowed = current.member
            && (current.result == BatchResult::ItemMissing
                || current.result == BatchResult::ItemRetry);
        if allowed {
            self.item_mut(job)?.duplicate = true;
        }
        self.set_last_item(job);
        self.finish(
            Command::HttpDuplicate { job },
            allowed,
            if allowed {
                HttpOutcome::DuplicateDelivered
            } else {
                HttpOutcome::ProjectionRejected
            },
            current.result,
            current.retry_owner,
            current.retry_after,
            self.projection.meta.batch_results.clone(),
        )
    }

    fn omit(&mut self, job: JobId) -> Result {
        let current = self.item(job)?.clone();
        let allowed = current.member
            && current.result == BatchResult::ItemMissing
            && !current.attempt_executed
            && current.attempts < MAX_ATTEMPTS;
        if allowed {
            // Exercise the public batch result validator: an omitted response
            // is converted to an item-local retry, never silently dropped.
            let request = &self
                .jobs
                .get(&job)
                .ok_or_else(|| std::io::Error::other("missing connector job"))?
                .request;
            let context = BatchItemContext {
                execution_id: id_from_model(current.execution_id)?,
                attempt_id: attempt_id_from_model(current.attempt_id)?,
                request,
            };
            let results = BatchResultSet::from_response(
                &[context],
                BatchResponse::PerItem(Vec::new()),
                BatchClassificationLimits {
                    retry_after_max: Duration::from_secs(MAX_RETRY_AFTER_TICKS as u64),
                    retry_after_fallback: Duration::from_secs(RETRY_AFTER_FALLBACK_TICKS as u64),
                },
                SystemTime::UNIX_EPOCH,
                Timestamp::ZERO,
            )?;
            if !matches!(
                results.outcomes().first().map(|outcome| &outcome.outcome),
                Some(JobOutcome::Retry { .. })
            ) {
                return Err(std::io::Error::other("omitted batch item was not retried").into());
            }
            let item = self.item_mut(job)?;
            item.omitted = true;
            item.result = BatchResult::ItemRetry;
            item.retry_owner = RetryOwner::EngineOwnsRetry;
            item.attempt_executed = true;
        }
        self.set_last_item(job);
        let result = if allowed {
            BatchResult::ItemRetry
        } else {
            current.result
        };
        let batch_result = self.update_batch_result(job, result);
        self.finish(
            Command::HttpOmit { job },
            allowed,
            if allowed {
                HttpOutcome::ItemOmitted
            } else {
                HttpOutcome::ProjectionRejected
            },
            result,
            if allowed {
                RetryOwner::EngineOwnsRetry
            } else {
                current.retry_owner
            },
            current.retry_after,
            batch_result,
        )
    }

    fn policy_id(&self) -> Result<HttpPolicyId> {
        self.executor
            .policy(&HttpPolicyId::try_new(C::policy_id())?)
            .map(|policy| policy.id().clone())
            .ok_or_else(|| std::io::Error::other("connector policy is not registered").into())
    }

    fn item(&self, job: JobId) -> Result<&Item> {
        self.projection
            .items
            .get(&job)
            .ok_or_else(|| std::io::Error::other("connector model item is absent").into())
    }

    fn item_mut(&mut self, job: JobId) -> Result<&mut Item> {
        self.projection
            .items
            .get_mut(&job)
            .ok_or_else(|| std::io::Error::other("connector model item is absent").into())
    }

    fn set_last_item(&mut self, job: JobId) {
        self.projection.meta.last_item = job;
    }

    fn update_batch_result(
        &mut self,
        job: JobId,
        result: BatchResult,
    ) -> BTreeMap<JobId, BatchResult> {
        if self.projection.meta.batch_members.contains(&job) {
            self.projection.meta.batch_results.insert(job, result);
        }
        self.projection.meta.batch_results.clone()
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The receipt preserves each command-correlated model field"
    )]
    fn finish(
        &mut self,
        command: Command,
        allowed: bool,
        outcome: HttpOutcome,
        result: BatchResult,
        owner: RetryOwner,
        retry_after: i64,
        results: BTreeMap<JobId, BatchResult>,
    ) -> Result {
        let job = command_job(&command);
        let affected = command_affected(&command);
        let members = self.projection.meta.batch_members.clone();
        self.projection.meta.last_outcome = outcome;
        self.projection.meta.batch_results = results.clone();
        let transition = LastTransition {
            operation: command_operation(&command),
            command: command.clone(),
            class: if allowed {
                ResultClass::AppliedClass
            } else {
                ResultClass::RejectedClass
            },
            outcome,
            affected,
            job,
            result,
            owner,
            retry_after,
            members: members.clone(),
            results: results.clone(),
        };
        self.projection.command = command;
        self.projection.transition = transition.clone();
        self.projection.result = if outcome == HttpOutcome::BatchPrepared {
            CommandResult::HttpBatchResult {
                transition,
                members,
                results,
            }
        } else if matches!(
            outcome,
            HttpOutcome::HttpRetry | HttpOutcome::TransportRetry | HttpOutcome::RetryAfterObserved
        ) {
            CommandResult::HttpRetryResult {
                transition,
                owner,
                retry_after,
            }
        } else if matches!(
            outcome,
            HttpOutcome::InvalidInputRejected
                | HttpOutcome::AuthorisationRejected
                | HttpOutcome::ProjectionRejected
        ) {
            CommandResult::HttpRejected { transition, result }
        } else {
            CommandResult::HttpApplied {
                transition,
                result,
                owner,
                retry_after,
            }
        };
        Ok(())
    }
}

impl<C: ConnectorConfig> Driver for ConnectorDriver<C> {
    type State = StateProjection;

    fn step(&mut self, step: &Step) -> Result {
        match step.action_taken.as_str() {
            "mbtInit" => *self = Self::try_default()?,
            "mbtObserve" => {}
            "mbtNondetStep" | "mbtStep" => {
                let command = self.command_from_step(step)?;
                let debug = format!("{command:?}");
                self.apply_command(command).map_err(|error| {
                    std::io::Error::other(format!("{} command {debug} failed: {error}", C::label()))
                })?;
            }
            action => {
                return Err(std::io::Error::other(format!(
                    "{} connector action not implemented: {action}",
                    C::label()
                ))
                .into());
            }
        }
        Ok(())
    }
}

fn run_async<F: Future>(future: F) -> Result<F::Output> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(future))
}

fn make_jobs(
    policy_id: &HttpPolicyId,
    destination_valid: bool,
    body_bytes: i64,
) -> Result<BTreeMap<JobId, HttpJob>> {
    [
        (JobId::JobA, 1_u8),
        (JobId::JobB, 2_u8),
        (JobId::JobC, 3_u8),
    ]
    .into_iter()
    .map(|(job, marker)| {
        let _ = marker;
        Ok((
            job,
            make_job(policy_id, destination_valid, body_bytes.max(0), false)?,
        ))
    })
    .collect()
}

fn make_job(
    policy_id: &HttpPolicyId,
    destination_valid: bool,
    body_bytes: i64,
    contains_secret: bool,
) -> Result<HttpJob> {
    let host = if destination_valid {
        "api.example.com"
    } else {
        "blocked.example.com"
    };
    let bounded = usize::try_from(body_bytes)
        .map_err(|_| std::io::Error::other("negative request body size"))?;
    let mut body = vec![0_u8; bounded];
    if contains_secret {
        const SECRET_MARKER: &[u8] = b"connector-secret";
        let marker_len = SECRET_MARKER.len().min(body.len());
        body[..marker_len].copy_from_slice(&SECRET_MARKER[..marker_len]);
    }
    let request = HttpRequest::try_new(HttpRequestInput {
        method: Method::POST,
        url: Url::parse(&format!("https://{host}/jobs/connector"))?,
        headers: HeaderMap::new(),
        body: Bytes::from(body),
    })?;
    Ok(HttpJob::new(policy_id.clone(), request))
}

fn scripted_result(
    status: HttpStatus,
    transport: TransportResult,
    retry_after: i64,
) -> Result<std::result::Result<HttpResponse, HttpRequestError>> {
    if transport != TransportResult::TransportOk {
        let kind = match transport {
            TransportResult::Timeout => HttpRequestErrorKind::Timeout,
            TransportResult::ConnectFailure => HttpRequestErrorKind::Connect,
            TransportResult::InvalidResponse => HttpRequestErrorKind::ResponseBody,
            TransportResult::TransportOk => HttpRequestErrorKind::Unknown,
        };
        return Ok(Err(HttpRequestError::Transport { kind }));
    }
    let status = match status {
        HttpStatus::Status2xx => StatusCode::OK,
        HttpStatus::Status408 => StatusCode::REQUEST_TIMEOUT,
        HttpStatus::Status425 => StatusCode::TOO_EARLY,
        HttpStatus::Status429 => StatusCode::TOO_MANY_REQUESTS,
        HttpStatus::Status4xx => StatusCode::BAD_REQUEST,
        HttpStatus::Status5xx => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let mut headers = HeaderMap::new();
    if retry_after != 0 {
        let value = if retry_after < 0 {
            "malformed".to_owned()
        } else {
            retry_after.to_string()
        };
        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_str(&value)
                .map_err(|_| std::io::Error::other("invalid scripted Retry-After"))?,
        );
    }
    Ok(Ok(HttpResponse::from_mock(
        status,
        headers,
        Vec::new(),
        Url::parse("https://api.example.com/response")?,
    )))
}

fn id_from_model(value: i64) -> Result<ExecutionId> {
    let byte = u8::try_from(value)
        .map_err(|_| std::io::Error::other("model execution ID is outside connector bounds"))?;
    Ok(ExecutionId::from([byte; 16]))
}

fn attempt_id_from_model(value: i64) -> Result<AttemptId> {
    let byte = u8::try_from(value)
        .map_err(|_| std::io::Error::other("model attempt ID is outside connector bounds"))?;
    Ok(AttemptId::from([byte; 16]))
}

fn authority_input(job: JobId, item: &Item) -> AuthorityInput {
    AuthorityInput {
        job,
        node: item.node,
        revision: item.revision,
        generation: item.generation,
        fence: item.fence,
        token: item.token,
        lease_until: item.lease_until,
        operation: item.operation,
        execution_id: item.execution_id,
        attempt_id: item.attempt_id,
    }
}

fn authority_matches(item: &Item, authority: &AuthorityInput) -> bool {
    authority.job == item.job
        && authority.node == item.node
        && authority.revision == item.revision
        && authority.generation == item.generation
        && authority.fence == item.fence
        && authority.token == item.token
        && authority.lease_until == item.lease_until
        && authority.operation == item.operation
        && authority.execution_id == item.execution_id
        && authority.attempt_id == item.attempt_id
        && item.lease_until > 0
        && item.member
        && !item.attempt_executed
        && item.result == BatchResult::ItemMissing
        && item.auth == AuthResult::Authorised
        && item.destination_valid
        && item.body_bytes <= MAX_INLINE_PAYLOAD_BYTES as i64
        && item.idempotency_header == item.execution_id
}

fn clamp_retry_after(value: i64) -> i64 {
    if value < 0 {
        RETRY_AFTER_FALLBACK_TICKS
    } else {
        value.min(MAX_RETRY_AFTER_TICKS)
    }
}

fn parse_auth_result(command: &str) -> AuthResult {
    if command.contains("SignFailure") {
        AuthResult::SignFailure
    } else if command.contains("MissingSecret") {
        AuthResult::MissingSecret
    } else if command.contains("Denied") {
        AuthResult::Denied
    } else {
        AuthResult::Authorised
    }
}

fn command_job(command: &Command) -> JobId {
    match command {
        Command::HttpPrepare { members } => {
            if members.is_empty() || members.contains(&JobId::JobA) {
                JobId::JobA
            } else if members.contains(&JobId::JobB) {
                JobId::JobB
            } else {
                JobId::JobC
            }
        }
        Command::HttpInput { job, .. }
        | Command::HttpAuthorize { job, .. }
        | Command::HttpProject { job, .. }
        | Command::HttpRetryCommand { job, .. }
        | Command::HttpDuplicate { job }
        | Command::HttpOmit { job } => *job,
        Command::HttpExecute { authority, .. } => authority.job,
    }
}

fn command_affected(command: &Command) -> BTreeSet<JobId> {
    match command {
        Command::HttpPrepare { members } => members.clone(),
        _ => BTreeSet::from([command_job(command)]),
    }
}

fn command_operation(command: &Command) -> OperationId {
    match command {
        Command::HttpExecute { authority, .. } => authority.operation,
        _ => OperationId::OperationA,
    }
}

fn initial_items() -> BTreeMap<JobId, Item> {
    [
        (JobId::JobA, initial_item(JobId::JobA, 1)),
        (JobId::JobB, initial_item(JobId::JobB, 2)),
        (JobId::JobC, initial_item(JobId::JobC, 3)),
    ]
    .into_iter()
    .collect()
}

fn initial_item(job: JobId, execution_id: i64) -> Item {
    Item {
        job,
        member: false,
        node: Node::NodeA,
        revision: 1,
        generation: 1,
        fence: 2,
        token: 3,
        lease_until: 3,
        operation: OperationId::OperationA,
        execution_id,
        attempt_id: 1,
        attempts: 0,
        attempt_executed: false,
        input_secret: false,
        idempotency_header: 0,
        destination_valid: true,
        invalid_input: false,
        body_bytes: 0,
        auth: AuthResult::Authorised,
        status: HttpStatus::Status2xx,
        transport: TransportResult::TransportOk,
        retry_after: 0,
        retry_owner: RetryOwner::NoRetry,
        result: BatchResult::ItemMissing,
        duplicate: false,
        omitted: false,
        outcome_present: false,
        outcome_job: job,
        outcome_attempt_id: 0,
        outcome_revision: 0,
        outcome_generation: 0,
        outcome_fence: 0,
        outcome_token: 0,
        outcome_lease_until: 0,
        outcome_operation: OperationId::OperationA,
    }
}

fn initial_meta() -> Meta {
    Meta {
        batch_members: BTreeSet::new(),
        batch_results: BTreeMap::new(),
        last_item: JobId::JobA,
        last_outcome: HttpOutcome::Initialised,
        engine_retries: 0,
        transport_retries: 0,
        last_projection: RequestDiagnostic {
            header_count: 0,
            body_bytes: 0,
            includes_url: false,
            includes_headers: false,
            includes_body: false,
        },
    }
}

fn initial_transition(command: Command) -> LastTransition {
    LastTransition {
        command,
        class: ResultClass::AppliedClass,
        outcome: HttpOutcome::Initialised,
        affected: BTreeSet::new(),
        job: JobId::JobA,
        operation: OperationId::OperationA,
        result: BatchResult::ItemMissing,
        owner: RetryOwner::NoRetry,
        retry_after: 0,
        members: BTreeSet::new(),
        results: BTreeMap::new(),
    }
}
