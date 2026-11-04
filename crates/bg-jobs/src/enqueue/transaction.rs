use bytes::Bytes;

use super::{authority, operation::ValidatedEnqueue};
use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    keys,
    model::{EnqueueDisposition, EnqueueResult, NewJob},
    store::{Check, CommitOutcome, JobStore, Mutation, StoreTransaction},
    time::Timestamp,
};

pub(super) async fn enqueue_new<S: JobStore>(
    system: &JobSystem<S>,
    request: ValidatedEnqueue<'_>,
    expected_dedupe: Option<Bytes>,
) -> JobResult<EnqueueResult, S::Error> {
    let (record, mutations) = request.build_state(system)?;
    let transaction = system
        .build_enqueue_transaction(&request, &record, mutations, expected_dedupe)
        .await?;
    resolve_enqueue_commit(system, &request, transaction).await
}

async fn resolve_enqueue_commit<S: JobStore>(
    system: &JobSystem<S>,
    request: &ValidatedEnqueue<'_>,
    transaction: StoreTransaction,
) -> JobResult<EnqueueResult, S::Error> {
    let outcome = match system.commit_durable(transaction).await {
        Ok(outcome) => outcome,
        Err(JobSystemError::UnknownCommit) => CommitOutcome::Unknown,
        Err(error) => return Err(error),
    };
    let disposition = match outcome {
        CommitOutcome::Committed => {
            return Ok(enqueue_result(
                &request.job,
                EnqueueDisposition::Enqueued,
                request.now,
            ));
        }
        CommitOutcome::Conflict => EnqueueDisposition::AlreadyPresent,
        CommitOutcome::Unknown => EnqueueDisposition::Enqueued,
    };
    authority::reconcile_after_commit(system, request, disposition).await
}

fn enqueue_result(job: &NewJob, disposition: EnqueueDisposition, now: Timestamp) -> EnqueueResult {
    EnqueueResult {
        job_id: job.job_id,
        disposition,
        wake: crate::time::WakeHint::from_timestamp(job.scheduled_at, now),
    }
}

impl<S: JobStore> JobSystem<S> {
    async fn build_enqueue_transaction(
        &self,
        request: &ValidatedEnqueue<'_>,
        record: &crate::model::JobRecordV1,
        mut mutations: Vec<Mutation>,
        expected_dedupe: Option<Bytes>,
    ) -> JobResult<StoreTransaction, S::Error> {
        let job = &request.job;
        let wake_key = keys::wake_key(self.namespace(), &record.queue)?;
        let current_wake = self
            .store()
            .get(wake_key.clone())
            .await
            .map_err(JobSystemError::Store)?;
        let mut checks = vec![Check::Absent(keys::job_key(self.namespace(), &job.job_id)?)];
        let operation_key = keys::operation_key(self.namespace(), &job.job_id)?;
        checks.push(Check::Absent(operation_key));
        let wake_check = crate::wake::apply(
            wake_key,
            current_wake,
            crate::wake::WakeUpdate::Lower(record.scheduled_at),
            &mut mutations,
        )?;
        if let Some(check) = wake_check {
            checks.push(check);
        }
        if let Some(admission) = super::deduplication::DedupeAdmission::try_new(
            self.namespace(),
            record,
            expected_dedupe,
        )? {
            admission.append(&mut checks, &mut mutations);
        }
        if let Some(catalog) = &request.catalog {
            catalog.append(&mut checks, &mut mutations);
        }
        crate::transition::checked_transaction(self, checks, mutations)
    }
}
