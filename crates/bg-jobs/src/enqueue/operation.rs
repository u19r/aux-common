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
    pub(super) catalog: Option<crate::catalog::CatalogAdmission>,
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
        crate::model::JobDefinition::try_from_request(
            &self.job,
            namespace,
            self.registration,
            self.digest,
        )
    }
}

pub(crate) async fn enqueue<S: JobStore>(
    system: &JobSystem<S>,
    job: NewJob,
    now: Timestamp,
) -> JobResult<EnqueueResult, S::Error> {
    EnqueueInput {
        job,
        now,
        existing_match: authority::ExistingJobMatch::ExactRequest,
        catalog: None,
    }
    .enqueue(system)
    .await
}

pub(crate) async fn ensure_seed<S: JobStore>(
    system: &JobSystem<S>,
    job: NewJob,
    now: Timestamp,
) -> JobResult<EnqueueResult, S::Error> {
    EnqueueInput {
        job,
        now,
        existing_match: authority::ExistingJobMatch::StableSeed,
        catalog: None,
    }
    .enqueue(system)
    .await
}

pub(crate) async fn ensure_configured_seed<S: JobStore>(
    system: &JobSystem<S>,
    job: NewJob,
    now: Timestamp,
) -> JobResult<EnqueueResult, S::Error> {
    EnqueueInput {
        job,
        now,
        existing_match: authority::ExistingJobMatch::ConfiguredSeed,
        catalog: None,
    }
    .enqueue(system)
    .await
}

pub(crate) async fn enqueue_scheduled_occurrence<S: JobStore>(
    system: &JobSystem<S>,
    job: NewJob,
    now: Timestamp,
    catalog: crate::catalog::CatalogAdmission,
) -> JobResult<EnqueueResult, S::Error> {
    EnqueueInput {
        job,
        now,
        existing_match: authority::ExistingJobMatch::StableSeed,
        catalog: Some(catalog),
    }
    .enqueue(system)
    .await
}

struct EnqueueInput {
    job: NewJob,
    now: Timestamp,
    existing_match: authority::ExistingJobMatch,
    catalog: Option<crate::catalog::CatalogAdmission>,
}

impl EnqueueInput {
    async fn enqueue<S: JobStore>(
        self,
        system: &JobSystem<S>,
    ) -> JobResult<EnqueueResult, S::Error> {
        let (registration, digest) = system.validate_enqueue_job(&self.job)?;
        let request = ValidatedEnqueue {
            job: self.job,
            now: self.now,
            existing_match: self.existing_match,
            catalog: self.catalog,
            registration,
            digest,
        };
        let result = request.enqueue_with_catalog(system).await?;
        system.observe(crate::observer::JobEvent::Enqueued {
            queue: registration.queue().clone(),
            disposition: result.disposition,
        });
        Ok(result)
    }
}

impl ValidatedEnqueue<'_> {
    async fn enqueue_with_catalog<S: JobStore>(
        mut self,
        system: &JobSystem<S>,
    ) -> JobResult<EnqueueResult, S::Error> {
        if matches!(
            self.existing_match,
            authority::ExistingJobMatch::ConfiguredSeed
        ) {
            let Some(catalog) = system
                .prepare_catalog_seed(&self.definition(system.namespace())?)
                .await?
            else {
                return Ok(EnqueueResult {
                    job_id: self.job.job_id,
                    disposition: EnqueueDisposition::AlreadyPresent,
                    wake: crate::time::WakeHint::None,
                });
            };
            self.catalog = Some(catalog);
        }
        enqueue_validated(system, self).await
    }
}

impl<S: JobStore> JobSystem<S> {
    fn validate_enqueue_job(
        &self,
        job: &NewJob,
    ) -> JobResult<(&HandlerRegistration, [u8; 32]), S::Error> {
        let registration = self
            .registry()
            .get_ref(&job.kind, job.schema_version)
            .ok_or(JobSystemError::UnregisteredHandler)?;
        job.validate()?;
        validate_fairness(&job.fairness, registration.fairness_policy())?;
        Ok((registration, Sha256::digest(&job.payload).into()))
    }

    pub(crate) fn enqueue_definition_digest(&self, job: &NewJob) -> JobResult<[u8; 32], S::Error> {
        let (registration, digest) = self.validate_enqueue_job(job)?;
        let definition = crate::model::JobDefinition::try_from_request(
            job,
            self.namespace(),
            registration,
            digest,
        )?;
        crate::codec::job_definition_digest(&definition).map_err(Into::into)
    }
}

async fn enqueue_validated<S: JobStore>(
    system: &JobSystem<S>,
    request: ValidatedEnqueue<'_>,
) -> JobResult<EnqueueResult, S::Error> {
    let job_key = keys::job_key(system.namespace(), &request.job.job_id)?;
    let authority =
        authority::read_enqueue_authority(system, &request.job, &job_key, request.now).await?;
    match authority {
        authority::EnqueueAuthority::Existing(encoded) => {
            let result = authority::reconcile_record(
                system,
                &request,
                &encoded,
                EnqueueDisposition::AlreadyPresent,
            )?;
            if let Some(catalog) = &request.catalog {
                catalog
                    .confirm_existing(system, crate::store::Check::Value(job_key, encoded))
                    .await?;
            }
            Ok(result)
        }
        authority::EnqueueAuthority::Deduplicated { job_id } => Ok(EnqueueResult {
            job_id,
            disposition: EnqueueDisposition::Deduplicated,
            wake: crate::time::WakeHint::from_timestamp(request.job.scheduled_at, request.now),
        }),
        authority::EnqueueAuthority::Missing { expected_dedupe } => {
            transaction::enqueue_new(system, request, expected_dedupe).await
        }
    }
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
