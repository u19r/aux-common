//! Public engine composition for producer-death conformance.

use std::{
    num::NonZeroU16,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use bg_jobs::{
    EffectMode, ExecutionContext, FairnessClass, FairnessPolicy, HandlerFuture, JobCatalog,
    JobHandler, JobId, JobKind, JobOutcome, Namespace, OutcomeCode, OwnerId, Priority, QueueName,
    RetryPreset, Timestamp, ValidationError,
    runtime::{JobSystem, JobSystemBuilder},
    store::JobStore,
    test_support::{
        TestProfile,
        raw::{HandlerDefinition, NewJob},
    },
};
use bytes::Bytes;

use crate::constants::RECOVERY_PAYLOAD;

struct RecoveryHandler {
    calls: Arc<AtomicU32>,
    outcome: JobOutcome,
}

impl JobHandler for RecoveryHandler {
    fn execute<'a>(&'a self, _: ExecutionContext<'a>, payload: &'a [u8]) -> HandlerFuture<'a> {
        if payload == RECOVERY_PAYLOAD {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
        let outcome = self.outcome.clone();
        Box::pin(async move { Ok(outcome) })
    }
}

pub(crate) fn recovery_system<S: JobStore>(
    store: S,
    namespace: Namespace,
    calls: Arc<AtomicU32>,
) -> Result<JobSystem<S>, ValidationError> {
    let mut catalog = JobCatalog::new();
    catalog.register_raw(
        HandlerDefinition {
            kind: JobKind::try_new("recovery")?,
            schema_version: NonZeroU16::MIN,
            queue: QueueName::try_new("default")?,
            effect_mode: EffectMode::Idempotent,
            cost_units: NonZeroU16::MIN,
            fairness_policy: FairnessPolicy::low_volume(),
            default_retry: bg_jobs::RetrySelection::Preset(RetryPreset::Interactive),
            default_timeout: Duration::from_secs(1),
            handler: RecoveryHandler {
                calls,
                outcome: produced_outcome()?,
            },
        },
        None,
    )?;
    let manifest = bg_jobs::CatalogManifest::try_new(
        bg_jobs::CatalogRevision::from(std::num::NonZeroU64::MIN),
        Vec::new(),
        vec![bg_jobs::runtime::ScheduleId::from([3; 16])],
    )?;
    JobSystemBuilder::new(store)
        .catalog(catalog.with_manifest(manifest))
        .namespace(namespace)
        .owner(
            OwnerId::generate().map_err(|_| ValidationError::InvalidValue {
                field: "recovery owner entropy",
            })?,
        )
        .scheduler(Arc::new(TestProfile::new()))
        .build()
}

pub(crate) fn recovery_job(id: u8) -> Result<NewJob, ValidationError> {
    Ok(NewJob {
        job_id: JobId::from([id; 16]),
        kind: JobKind::try_new("recovery")?,
        schema_version: NonZeroU16::MIN,
        payload: Bytes::from_static(RECOVERY_PAYLOAD),
        fairness: FairnessClass::low_volume(),
        ordering_key: None,
        priority: Priority::Default,
        scheduled_at: Timestamp::ZERO,
        expires_at: None,
        retry_override: None,
        deduplication: None,
    })
}

pub(crate) fn produced_outcome() -> Result<JobOutcome, ValidationError> {
    Ok(JobOutcome::Complete(OutcomeCode::try_new(
        "produced-before-crash",
    )?))
}

pub(crate) fn recovery_schedule() -> Result<bg_jobs::runtime::RecurringSchedule, ValidationError> {
    use bg_jobs::runtime::{
        Cadence, CronExpression, JobTemplate, JobTemplateInput, MisfirePolicy, OverlapPolicy,
        RecurringSchedule, RecurringScheduleInput, ScheduleId,
    };
    Ok(RecurringSchedule::new(RecurringScheduleInput {
        schedule_id: ScheduleId::from([3; 16]),
        job_template: JobTemplate::try_new(JobTemplateInput {
            kind: JobKind::try_new("recovery")?,
            schema_version: NonZeroU16::MIN,
            payload: Bytes::from_static(RECOVERY_PAYLOAD),
            fairness: FairnessClass::low_volume(),
            ordering_key: None,
            priority: Priority::Default,
            expires_after: None,
            retry_override: None,
            deduplication: None,
        })?,
        cadence: Cadence::CronUtc(CronExpression::try_new("0 * * * *")?),
        misfire: MisfirePolicy::FireOnce,
        overlap: OverlapPolicy::Forbid,
        enabled: true,
    }))
}
