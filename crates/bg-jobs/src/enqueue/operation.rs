use sha2::{Digest, Sha256};

use super::{authority, transaction};
use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError, ValidationError},
    keys,
    model::{EnqueueDisposition, EnqueueResult, NewJob},
    policy::{FairnessClass, FairnessPolicy},
    registry::HandlerRegistration,
    store::JobStore,
    time::Timestamp,
};

pub(super) struct ValidatedEnqueue<'a> {
    pub(super) job: NewJob,
    pub(super) registration: &'a HandlerRegistration,
    pub(super) digest: [u8; 32],
    pub(super) now: Timestamp,
    pub(super) existing_match: authority::ExistingJobMatch,
}

impl ValidatedEnqueue<'_> {
    pub(super) fn definition<'a>(
        &'a self,
        namespace: &'a crate::ids::Namespace,
    ) -> Result<crate::model::JobDefinition<'a>, crate::error::StoreDataError> {
        Ok(crate::model::JobDefinition {
            job_id: self.job.job_id,
            namespace,
            queue: self.registration.queue(),
            kind: &self.job.kind,
            schema_version: self.job.schema_version,
            payload_length: u32::try_from(self.job.payload.len())
                .map_err(|_| crate::error::StoreDataError::LengthOverflow)?,
            payload_digest: self.digest,
            fairness: &self.job.fairness,
            ordering_key: self.job.ordering_key.as_ref(),
            priority: self.job.priority,
            expires_at: self.job.expires_at,
            policy: super::state::build_policy(&self.job, self.registration),
            deduplication: self.job.deduplication.as_ref(),
        })
    }
}

pub(crate) async fn enqueue<S: JobStore>(
    system: &JobSystem<S>,
    job: NewJob,
    now: Timestamp,
) -> JobResult<EnqueueResult, S::Error> {
    enqueue_with_match(system, job, now, authority::ExistingJobMatch::ExactRequest).await
}

pub(crate) async fn ensure_seed<S: JobStore>(
    system: &JobSystem<S>,
    job: NewJob,
    now: Timestamp,
) -> JobResult<EnqueueResult, S::Error> {
    enqueue_with_match(system, job, now, authority::ExistingJobMatch::StableSeed).await
}

async fn enqueue_with_match<S: JobStore>(
    system: &JobSystem<S>,
    job: NewJob,
    now: Timestamp,
    existing_match: authority::ExistingJobMatch,
) -> JobResult<EnqueueResult, S::Error> {
    let registration = system
        .registry()
        .get_ref(&job.kind, job.schema_version)
        .ok_or(JobSystemError::UnregisteredHandler)?;
    job.validate()?;
    validate_fairness(&job.fairness, registration.fairness_policy())?;
    let digest: [u8; 32] = Sha256::digest(&job.payload).into();
    let queue = registration.queue().clone();
    let request = ValidatedEnqueue {
        job,
        registration,
        digest,
        now,
        existing_match,
    };
    let result = enqueue_validated(system, request).await;
    if let Ok(result) = &result {
        system.observe(crate::observer::JobEvent::Enqueued {
            queue,
            disposition: result.disposition,
        });
    }
    result
}

async fn enqueue_validated<S: JobStore>(
    system: &JobSystem<S>,
    request: ValidatedEnqueue<'_>,
) -> JobResult<EnqueueResult, S::Error> {
    let job_key = keys::job_key(system.namespace(), &request.job.job_id)?;
    let authority =
        authority::read_enqueue_authority(system, &request.job, &job_key, request.now).await?;
    match authority {
        authority::EnqueueAuthority::Existing(encoded) => authority::reconcile_record(
            system,
            &request,
            &encoded,
            EnqueueDisposition::AlreadyPresent,
        ),
        authority::EnqueueAuthority::Deduplicated { job_id } => Ok(EnqueueResult {
            job_id,
            disposition: EnqueueDisposition::Deduplicated,
            wake: crate::time::WakeHint::from_timestamp(request.job.scheduled_at, request.now),
        }),
        authority::EnqueueAuthority::Missing {
            expected_dedupe,
            prior_fence,
        } => enqueue_missing_job(system, request, expected_dedupe, prior_fence).await,
    }
}

async fn enqueue_missing_job<S: JobStore>(
    system: &JobSystem<S>,
    request: ValidatedEnqueue<'_>,
    expected_dedupe: Option<bytes::Bytes>,
    prior_fence: Option<authority::PriorFenceAuthority>,
) -> JobResult<EnqueueResult, S::Error> {
    if let Some(prior) = &prior_fence
        && let Some(result) = authority::reconcile_completed_seed(
            &request,
            system.namespace(),
            prior,
            EnqueueDisposition::AlreadyPresent,
        )?
    {
        return Ok(result);
    }
    transaction::enqueue_new(system, request, expected_dedupe, prior_fence).await
}

fn validate_fairness(
    fairness: &FairnessClass,
    policy: FairnessPolicy,
) -> Result<(), ValidationError> {
    match (fairness, policy) {
        (FairnessClass::Scoped(_), FairnessPolicy::Scoped { .. })
        | (FairnessClass::LowVolume, FairnessPolicy::LowVolume) => Ok(()),
        _ => Err(ValidationError::InvalidValue {
            field: "fairness policy",
        }),
    }
}
