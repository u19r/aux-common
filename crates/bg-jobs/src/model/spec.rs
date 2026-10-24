use std::{marker::PhantomData, num::NonZeroU16, sync::Arc, time::Duration};

use bytes::Bytes;

use crate::{
    error::ValidationError,
    ids::{JobId, JobKind, OrderingKey, QueueName},
    model::{HandlerDefinition, JobHandler, NewJob},
    policy::{Deduplication, EffectMode, FairnessClass, FairnessPolicy, Priority, RetrySelection},
    time::Timestamp,
};

type JobEncoder<T> = dyn Fn(&T) -> Result<Bytes, ValidationError> + Send + Sync + 'static;

/// A typed registration assembled by a consuming application.
pub struct JobSpec<T, H> {
    kind: JobKind,
    schema_version: NonZeroU16,
    queue: QueueName,
    effect_mode: Option<EffectMode>,
    cost_units: NonZeroU16,
    fairness_policy: Option<FairnessPolicy>,
    default_retry: Option<RetrySelection>,
    default_timeout: Option<Duration>,
    handler: H,
    codec: Arc<JobEncoder<T>>,
    payload: PhantomData<fn() -> T>,
}

impl<T: 'static, H> JobSpec<T, H> {
    /// Starts a single-handler specification. Safety-sensitive policy is
    /// selected explicitly through the fluent methods below.
    pub fn new<C>(
        kind: JobKind,
        schema_version: NonZeroU16,
        queue: QueueName,
        handler: H,
        codec: C,
    ) -> Self
    where
        C: Fn(&T) -> Result<Bytes, ValidationError> + Send + Sync + 'static,
    {
        Self {
            kind,
            schema_version,
            queue,
            effect_mode: None,
            cost_units: NonZeroU16::MIN,
            fairness_policy: None,
            default_retry: None,
            default_timeout: None,
            handler,
            codec: Arc::new(codec),
            payload: PhantomData,
        }
    }

    /// Applies the complete execution policy in one place. Safety-sensitive
    /// handler policy is deliberately atomic at the registration boundary.
    pub fn policy(
        self,
        effect_mode: EffectMode,
        fairness_policy: FairnessPolicy,
        retry: RetrySelection,
        timeout: Duration,
    ) -> Self {
        Self {
            effect_mode: Some(effect_mode),
            fairness_policy: Some(fairness_policy),
            default_retry: Some(retry),
            default_timeout: Some(timeout),
            ..self
        }
    }

    /// Overrides the default single cost unit when the handler is heavier.
    pub fn cost_units(mut self, cost_units: NonZeroU16) -> Self {
        self.cost_units = cost_units;
        self
    }

    pub(crate) fn into_parts(
        self,
    ) -> Result<(HandlerDefinition<H>, JobHandle<T>), ValidationError>
    where H: JobHandler {
        let effect_mode = self.effect_mode.ok_or(ValidationError::InvalidValue {
            field: "handler effect mode",
        })?;
        let fairness_policy = self.fairness_policy.ok_or(ValidationError::InvalidValue {
            field: "handler fairness policy",
        })?;
        let default_retry = self.default_retry.ok_or(ValidationError::InvalidValue {
            field: "handler retry policy",
        })?;
        let default_timeout = self.default_timeout.ok_or(ValidationError::InvalidValue {
            field: "handler timeout",
        })?;
        let handle = JobHandle {
            kind: self.kind.clone(),
            schema_version: self.schema_version,
            codec: self.codec,
            payload: PhantomData,
        };
        let definition = HandlerDefinition {
            kind: self.kind,
            schema_version: self.schema_version,
            queue: self.queue,
            effect_mode,
            cost_units: self.cost_units,
            fairness_policy,
            default_retry,
            default_timeout,
            handler: self.handler,
        };
        definition.validate()?;
        Ok((definition, handle))
    }
}

impl<H> JobSpec<Bytes, H> {
    /// Starts a specification for handlers whose payload is already encoded.
    /// This keeps the common identity codec out of every consumer catalog.
    pub fn bytes(kind: JobKind, schema_version: NonZeroU16, queue: QueueName, handler: H) -> Self {
        Self::new(kind, schema_version, queue, handler, clone_bytes)
    }
}

impl<H> JobSpec<(), H> {
    /// Starts a specification for handlers whose durable payload is empty.
    pub fn unit(kind: JobKind, schema_version: NonZeroU16, queue: QueueName, handler: H) -> Self {
        Self::new(kind, schema_version, queue, handler, |_: &()| {
            Ok::<Bytes, ValidationError>(Bytes::new())
        })
    }
}

fn clone_bytes(payload: &Bytes) -> Result<Bytes, ValidationError> {
    Ok(payload.clone())
}

/// A typed handle for enqueueing payloads registered in a JobCatalog.
pub struct JobHandle<T> {
    kind: JobKind,
    schema_version: NonZeroU16,
    codec: Arc<JobEncoder<T>>,
    payload: PhantomData<fn() -> T>,
}

impl<T> Clone for JobHandle<T> {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind.clone(),
            schema_version: self.schema_version,
            codec: Arc::clone(&self.codec),
            payload: PhantomData,
        }
    }
}

impl<T: 'static> JobHandle<T> {
    pub(crate) fn new_job(
        &self,
        payload: T,
        options: EnqueueOptions,
        job_id: JobId,
        now: Timestamp,
    ) -> Result<NewJob, ValidationError> {
        JobSeed::new_encoded(
            job_id,
            self.kind.clone(),
            self.schema_version,
            (self.codec)(&payload)?,
            options,
            now,
        )
        .map(JobSeed::into_new_job)
    }

    /// Returns the validated kind captured by this handle.
    pub fn kind(&self) -> &JobKind {
        &self.kind
    }

    /// Returns the validated schema version captured by this handle.
    pub const fn schema_version(&self) -> NonZeroU16 {
        self.schema_version
    }

    /// Builds a stable seed for this handler. A seed must supply its own
    /// stable job ID so restarting a process cannot create a new controller.
    pub fn seed(
        &self,
        payload: T,
        options: EnqueueOptions,
        now: Timestamp,
    ) -> Result<JobSeed, ValidationError> {
        let job_id = options.job_id.ok_or(ValidationError::InvalidValue {
            field: "seed job id",
        })?;
        Ok(JobSeed(self.new_job(payload, options, job_id, now)?))
    }
}

/// A stable seed produced by a typed handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobSeed(NewJob);

impl JobSeed {
    /// Creates a stable seed from an already encoded payload.
    ///
    /// The options must include a stable job ID. The common constructor owns
    /// record validation and derives the schedule from `now` when no explicit
    /// schedule is supplied, so consumers do not construct a raw `NewJob`.
    pub fn new(
        kind: JobKind,
        schema_version: NonZeroU16,
        payload: Bytes,
        options: EnqueueOptions,
        now: Timestamp,
    ) -> Result<Self, ValidationError> {
        let job_id = options.job_id.ok_or(ValidationError::InvalidValue {
            field: "seed job id",
        })?;
        Self::new_encoded(job_id, kind, schema_version, payload, options, now)
    }

    fn new_encoded(
        job_id: JobId,
        kind: JobKind,
        schema_version: NonZeroU16,
        payload: Bytes,
        options: EnqueueOptions,
        now: Timestamp,
    ) -> Result<Self, ValidationError> {
        let job = NewJob {
            job_id,
            kind,
            schema_version,
            payload,
            fairness: options.fairness,
            ordering_key: options.ordering_key,
            priority: options.priority,
            scheduled_at: options.scheduled_at.unwrap_or(now),
            expires_at: options.expires_at,
            retry_override: options.retry_override,
            deduplication: options.deduplication,
        };
        job.validate()?;
        Ok(Self(job))
    }

    /// Returns the stable identity used when replaying this seed.
    pub const fn job_id(&self) -> JobId {
        self.0.job_id
    }

    /// Returns the registered handler identity.
    pub fn kind(&self) -> &JobKind {
        &self.0.kind
    }

    /// Returns the persisted schema version.
    pub const fn schema_version(&self) -> NonZeroU16 {
        self.0.schema_version
    }

    /// Returns the encoded payload for diagnostics and deterministic tests.
    pub fn payload(&self) -> &Bytes {
        &self.0.payload
    }

    /// Returns the selected fairness lane.
    pub fn fairness(&self) -> &FairnessClass {
        &self.0.fairness
    }

    /// Returns the optional ordering group.
    pub fn ordering_key(&self) -> Option<&OrderingKey> {
        self.0.ordering_key.as_ref()
    }

    /// Returns the selected priority lane.
    pub const fn priority(&self) -> Priority {
        self.0.priority
    }

    /// Returns the first schedule timestamp.
    pub const fn scheduled_at(&self) -> Timestamp {
        self.0.scheduled_at
    }

    /// Returns the optional expiry boundary.
    pub const fn expires_at(&self) -> Option<Timestamp> {
        self.0.expires_at
    }

    pub(crate) fn into_new_job(self) -> NewJob {
        self.0
    }
}

/// Enqueue values owned by the product boundary.
#[derive(Clone, Debug)]
pub struct EnqueueOptions {
    job_id: Option<JobId>,
    fairness: FairnessClass,
    ordering_key: Option<OrderingKey>,
    priority: Priority,
    scheduled_at: Option<Timestamp>,
    expires_at: Option<Timestamp>,
    retry_override: Option<RetrySelection>,
    deduplication: Option<Deduplication>,
}

impl EnqueueOptions {
    /// Starts an enqueue with the required fairness class and safe defaults.
    pub fn new(fairness: FairnessClass) -> Self {
        Self {
            job_id: None,
            fairness,
            ordering_key: None,
            priority: Priority::Default,
            scheduled_at: None,
            expires_at: None,
            retry_override: None,
            deduplication: None,
        }
    }

    /// Supplies a stable ID when the enqueue must be replayable or seeded.
    pub fn job_id(mut self, job_id: JobId) -> Self {
        self.job_id = Some(job_id);
        self
    }

    /// Schedules the job at an explicit wall-clock timestamp.
    pub fn scheduled_at(mut self, scheduled_at: Timestamp) -> Self {
        self.scheduled_at = Some(scheduled_at);
        self
    }

    /// Adds an expiry boundary.
    pub fn expires_at(mut self, expires_at: Timestamp) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Adds a product-owned ordering group.
    pub fn ordering_key(mut self, ordering_key: OrderingKey) -> Self {
        self.ordering_key = Some(ordering_key);
        self
    }

    /// Selects a priority lane.
    pub fn priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    /// Overrides the registered retry policy for this enqueue.
    pub fn retry(mut self, retry: RetrySelection) -> Self {
        self.retry_override = Some(retry);
        self
    }

    /// Retains a bounded deduplication key.
    pub fn deduplicate(mut self, deduplication: Deduplication) -> Self {
        self.deduplication = Some(deduplication);
        self
    }

    pub(crate) fn job_id_value(&self) -> Option<JobId> {
        self.job_id
    }

    /// Returns an explicitly selected schedule, if any.
    #[cfg(test)]
    pub(crate) fn scheduled_at_value(&self) -> Option<Timestamp> {
        self.scheduled_at
    }

    /// Returns an explicitly selected expiry, if any.
    #[cfg(test)]
    pub(crate) fn expires_at_value(&self) -> Option<Timestamp> {
        self.expires_at
    }

    /// Returns an explicitly selected retry override, if any.
    #[cfg(test)]
    pub(crate) fn retry_override(&self) -> Option<RetrySelection> {
        self.retry_override
    }
}
