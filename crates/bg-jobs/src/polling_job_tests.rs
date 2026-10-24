use std::{
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use crate::{
    FairnessPolicy, JobHandler, JobId, JobOutcome, JobPoller, PollActivity, PollFuture, PollingJob,
    Timestamp,
    test_helper::{FakeStore, block_on, low_volume_job, system},
};

enum PollBehavior {
    Active,
    Idle,
    Failed,
    Cancelled,
}

struct TestPoller {
    behavior: PollBehavior,
    calls: Arc<AtomicUsize>,
}

impl JobPoller for TestPoller {
    fn poll<'a>(&'a self, context: crate::ExecutionContext<'a>) -> PollFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            match self.behavior {
                PollBehavior::Active => Ok(PollActivity::Active),
                PollBehavior::Idle => Ok(PollActivity::Idle),
                PollBehavior::Failed => Err(std::io::Error::other("unavailable").into()),
                PollBehavior::Cancelled => {
                    context.cancellation().cancel();
                    Ok(PollActivity::Active)
                }
            }
        })
    }
}

#[test]
fn given_a_failed_poll_when_executing_then_the_runtime_receives_the_error_for_bounded_retry() {
    let system = system(FakeStore::new(), FairnessPolicy::low_volume(), 1);
    let seed = low_volume_job(1, Timestamp::ZERO);
    block_on(system.enqueue_raw(seed.clone(), Timestamp::ZERO)).unwrap();
    let claim = block_on(system.claim(seed.job_id, Timestamp::ZERO)).unwrap();
    let handler = PollingJob::new(
        TestPoller {
            behavior: PollBehavior::Failed,
            calls: Arc::new(AtomicUsize::new(0)),
        },
        NonZeroU32::MIN,
    );
    assert!(block_on(handler.execute(claim.context().unwrap(), claim.payload())).is_err());
}

#[test]
fn given_active_and_idle_discovery_when_polling_then_only_idle_passes_wait() {
    for (behavior, expected) in [(PollBehavior::Active, 0), (PollBehavior::Idle, 1_000)] {
        let system = system(FakeStore::new(), FairnessPolicy::low_volume(), 1);
        block_on(system.ensure_seed_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
            .unwrap();
        let claim = block_on(system.claim(JobId::from([1; 16]), Timestamp::ZERO)).unwrap();
        let handler = PollingJob::new(
            TestPoller {
                behavior,
                calls: Arc::new(AtomicUsize::new(0)),
            },
            NonZeroU32::MIN,
        );
        let outcome = block_on(handler.execute(claim.context().unwrap(), claim.payload())).unwrap();
        assert!(
            matches!(outcome, JobOutcome::Continue { not_before, .. } if if expected == 0 { not_before == Timestamp::ZERO } else { (1600..=2000).contains(&not_before.as_millis()) })
        );
    }
}

#[test]
fn given_cancellation_before_or_during_a_poll_when_execution_finishes_then_no_continuation_is_scheduled()
 {
    for cancelled_before in [true, false] {
        let system = system(FakeStore::new(), FairnessPolicy::low_volume(), 1);
        block_on(system.ensure_seed_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
            .unwrap();
        let claim = block_on(system.claim(JobId::from([1; 16]), Timestamp::ZERO)).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let handler = PollingJob::new(
            TestPoller {
                behavior: PollBehavior::Cancelled,
                calls: calls.clone(),
            },
            NonZeroU32::MIN,
        );
        if cancelled_before {
            claim.cancellation().cancel();
        }
        let outcome = block_on(handler.execute(claim.context().unwrap(), claim.payload())).unwrap();
        assert!(matches!(outcome, JobOutcome::Cancelled));
        assert_eq!(calls.load(Ordering::SeqCst), usize::from(!cancelled_before));
    }
}
