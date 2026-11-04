//! Consumer-visible recovery of accepted commands after permanent producer
//! loss.

use std::{
    future::{Future, poll_fn},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    task::Poll,
};

use bg_jobs::{
    DriveBudget, JobId, JobSystemError, Namespace, QueueSelection, Timestamp,
    runtime::MonotonicDeadline, store::JobStore,
};

use crate::{
    ConformanceError,
    recovery_fixture::{produced_outcome, recovery_job, recovery_system},
    recovery_store::RecoveryStore,
};

type RecoveryResult<T, E> = Result<T, ConformanceError<JobSystemError<E>>>;

/// Evidence from accepted enqueue and completion recovery with permanently
/// abandoned producers. This does not assert external-effect exactly-once
/// behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryReport {
    pub recovered_enqueues: u32,
    pub recovered_completions: u32,
    pub recovered_schedules: u32,
    pub handler_executions: u32,
}

/// Runs public enqueue, drive, claim, completion, and replacement recovery over
/// a consumer's real adapter. Supply an empty, externally unique namespace.
/// The adapter's own deadlines must bound native futures; this runtime-neutral
/// harness deliberately provides no timer or process-death oracle.
/// Both original producers are dropped after durable admission and never
/// return. The namespace retains its bounded journal frontiers and existing
/// lifecycle metadata so callers can inspect physical storage after this proof.
pub async fn run_recovery<S: JobStore + Clone>(
    producer: S,
    replacement: S,
    namespace: Namespace,
) -> RecoveryResult<RecoveryReport, S::Error> {
    let harness = RecoveryHarness {
        producer,
        replacement,
        namespace,
        calls: Arc::new(AtomicU32::new(0)),
    };
    let enqueues = harness.recover_enqueue().await?;
    let completions = harness.recover_completion().await?;
    let schedules = harness.recover_schedule().await?;
    let handler_executions = harness.calls.load(Ordering::SeqCst);
    Ok(RecoveryReport {
        recovered_enqueues: enqueues,
        recovered_completions: completions,
        recovered_schedules: schedules,
        handler_executions,
    })
}

struct RecoveryHarness<S> {
    producer: S,
    replacement: S,
    namespace: Namespace,
    calls: Arc<AtomicU32>,
}

impl<S: JobStore + Clone> RecoveryHarness<S> {
    async fn recover_schedule(&self) -> RecoveryResult<u32, S::Error> {
        let interrupted = RecoveryStore::new(self.producer.clone());
        let original = recovery_system(
            interrupted.clone(),
            self.namespace.clone(),
            self.calls.clone(),
        )
        .map_err(|_| ConformanceError::Invalid("schedule producer"))?;
        original
            .recover_commits()
            .await
            .map_err(ConformanceError::Store)?;
        original
            .initialize_catalog()
            .await
            .map_err(ConformanceError::Store)?;
        let definition = crate::recovery_fixture::recovery_schedule()
            .map_err(|_| ConformanceError::Invalid("schedule definition"))?;
        let initial = bg_jobs::runtime::ScheduleCursor::new(Some(Timestamp::ZERO), true);
        let now = Timestamp::from_millis(3 * 60 * 60 * 1_000);
        interrupted.arm();
        abandon_after_acceptance(
            original.materialize_schedule(&definition, &initial, now),
            &interrupted.accepted,
        )
        .await?;
        drop(original);
        let replacement = recovery_system(
            self.replacement.clone(),
            self.namespace.clone(),
            self.calls.clone(),
        )
        .map_err(|_| ConformanceError::Invalid("schedule replacement"))?;
        let recovered = replacement
            .recover_commits()
            .await
            .map_err(ConformanceError::Store)?;
        if recovered != 1 {
            return Err(ConformanceError::Invalid(
                "accepted schedule admission was not recovered",
            ));
        }
        self.verify_recovered_schedule(&replacement, &definition, &initial, now)
            .await?;
        Ok(recovered)
    }

    async fn verify_recovered_schedule(
        &self,
        replacement: &bg_jobs::runtime::JobSystem<S>,
        definition: &bg_jobs::runtime::RecurringSchedule,
        initial: &bg_jobs::runtime::ScheduleCursor,
        now: Timestamp,
    ) -> RecoveryResult<(), S::Error> {
        let report = replacement
            .materialize_schedule(definition, initial, now)
            .await
            .map_err(ConformanceError::Store)?;
        if !report.occurrences.is_empty()
            || !report.cursor.is_active()
            || report.cursor.watermark() != Some(now)
        {
            return Err(ConformanceError::Invalid(
                "recovered occurrence cursor lost atomic admission",
            ));
        }
        let job_id = bg_jobs::runtime::ScheduleOccurrence {
            schedule_id: definition.schedule_id,
            intended_at: now,
            generation: 0,
        }
        .job_id();
        let claim = replacement
            .claim(job_id, now)
            .await
            .map_err(ConformanceError::Store)?;
        if claim.payload().as_ref() != crate::constants::RECOVERY_PAYLOAD {
            return Err(ConformanceError::Invalid(
                "recovered occurrence payload changed",
            ));
        }
        replacement
            .complete(
                claim,
                produced_outcome().map_err(|_| ConformanceError::Invalid("schedule outcome"))?,
                now,
            )
            .await
            .map_err(ConformanceError::Store)?;
        let next = replacement
            .materialize_schedule(definition, initial, now)
            .await
            .map_err(ConformanceError::Store)?;
        if !next.occurrences.is_empty() || next.cursor.is_active() {
            return Err(ConformanceError::Invalid(
                "completed occurrence repeated or overlap stayed blocked",
            ));
        }
        Ok(())
    }

    async fn recover_enqueue(&self) -> RecoveryResult<u32, S::Error> {
        let interrupted = RecoveryStore::new(self.producer.clone());
        interrupted.arm();
        let original = recovery_system(
            interrupted.clone(),
            self.namespace.clone(),
            self.calls.clone(),
        )
        .map_err(|_| ConformanceError::Invalid("recovery system"))?;
        let job = recovery_job(1).map_err(|_| ConformanceError::Invalid("recovery enqueue"))?;
        abandon_after_acceptance(
            original.enqueue_raw(job, Timestamp::ZERO),
            &interrupted.accepted,
        )
        .await?;
        drop(original);
        let replacement = recovery_system(
            self.replacement.clone(),
            self.namespace.clone(),
            self.calls.clone(),
        )
        .map_err(|_| ConformanceError::Invalid("replacement system"))?;
        self.finish_recovered_enqueue(&replacement).await
    }

    async fn finish_recovered_enqueue(
        &self,
        replacement: &bg_jobs::runtime::JobSystem<S>,
    ) -> RecoveryResult<u32, S::Error> {
        let recovered = replacement
            .recover_commits()
            .await
            .map_err(ConformanceError::Store)?;
        if recovered != 1 {
            return Err(ConformanceError::Invalid(
                "accepted enqueue was not recovered",
            ));
        }
        let request = DriveBudget::try_tiny(QueueSelection::all())
            .and_then(|budget| budget.request_at(MonotonicDeadline::ZERO))
            .map_err(|_| ConformanceError::Invalid("recovery drive budget"))?;
        let report = replacement
            .drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO)
            .await
            .map_err(ConformanceError::Store)?;
        if report.counts.claimed != 1
            || report.counts.succeeded != 1
            || self.calls.load(Ordering::SeqCst) != 1
        {
            return Err(ConformanceError::Invalid(
                "recovered enqueue did not execute its exact payload once",
            ));
        }
        Ok(recovered)
    }

    async fn recover_completion(&self) -> RecoveryResult<u32, S::Error> {
        let interrupted = RecoveryStore::new(self.producer.clone());
        let original = recovery_system(
            interrupted.clone(),
            self.namespace.clone(),
            self.calls.clone(),
        )
        .map_err(|_| ConformanceError::Invalid("completion producer"))?;
        original
            .recover_commits()
            .await
            .map_err(ConformanceError::Store)?;
        let claim = self.prepare_completion(&original).await?;
        interrupted.arm();
        let outcome =
            produced_outcome().map_err(|_| ConformanceError::Invalid("produced outcome"))?;
        abandon_after_acceptance(
            original.complete(claim, outcome, Timestamp::ZERO),
            &interrupted.accepted,
        )
        .await?;
        drop(original);
        let replacement = recovery_system(
            self.replacement.clone(),
            self.namespace.clone(),
            self.calls.clone(),
        )
        .map_err(|_| ConformanceError::Invalid("completion replacement"))?;
        self.finish_recovered_completion(&replacement).await
    }

    async fn prepare_completion(
        &self,
        producer: &bg_jobs::runtime::JobSystem<RecoveryStore<S>>,
    ) -> RecoveryResult<bg_jobs::test_support::raw::ClaimedJob, S::Error> {
        let job = recovery_job(2).map_err(|_| ConformanceError::Invalid("completion job"))?;
        producer
            .enqueue_raw(job, Timestamp::ZERO)
            .await
            .map_err(ConformanceError::Store)?;
        let claim = producer
            .claim(JobId::from([2; 16]), Timestamp::ZERO)
            .await
            .map_err(ConformanceError::Store)?;
        if claim.payload().as_ref() != crate::constants::RECOVERY_PAYLOAD {
            return Err(ConformanceError::Invalid(
                "completion input payload changed",
            ));
        }
        Ok(claim)
    }

    async fn finish_recovered_completion(
        &self,
        replacement: &bg_jobs::runtime::JobSystem<S>,
    ) -> RecoveryResult<u32, S::Error> {
        let recovered = replacement
            .recover_commits()
            .await
            .map_err(ConformanceError::Store)?;
        if recovered != 1 {
            return Err(ConformanceError::Invalid(
                "accepted completion was not recovered",
            ));
        }
        if !matches!(
            replacement
                .claim(JobId::from([2; 16]), Timestamp::ZERO)
                .await,
            Err(JobSystemError::NotFound)
        ) {
            return Err(ConformanceError::Invalid(
                "accepted completion left claimable work",
            ));
        }
        if replacement
            .recover_commits()
            .await
            .map_err(ConformanceError::Store)?
            != 0
        {
            return Err(ConformanceError::Invalid(
                "settled completion remained unresolved",
            ));
        }
        if self.calls.load(Ordering::SeqCst) != 1 {
            return Err(ConformanceError::Invalid(
                "recovery reran a producer's handler",
            ));
        }
        Ok(recovered)
    }
}

pub(crate) async fn abandon_after_acceptance<F, T, E>(
    future: F,
    accepted: &AtomicBool,
) -> Result<(), ConformanceError<E>>
where
    F: Future<Output = Result<T, E>>,
{
    let mut producer = Box::pin(future);
    poll_fn(|context| {
        let result = producer.as_mut().poll(context);
        if accepted.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(ConformanceError::Store(error))),
            Poll::Ready(Ok(_)) => Poll::Ready(Err(ConformanceError::Invalid(
                "producer returned before durable admission was interrupted",
            ))),
        }
    })
    .await
}
