use std::{fmt, future::Future, sync::Arc};

use bg_jobs::{
    AttemptId, DriveReport, DriveStopReason, EnqueueResult, ExecutionId, JobCatalog, JobId,
    JobStore, Namespace, OwnerId, Timestamp, WakeHint,
    observer::{JobEvent, SafeJobErrorEvent},
    runtime::{JobSystem, JobSystemBuilder},
    test_support::{
        FakeStore,
        raw::{
            ActivePulseStopReason, Batch, BatchApplication, CompletionDetails, FairnessRejection,
            NewJob, RedriveResult, TransitionAuthority,
        },
    },
};
use cucumber::World;

mod common;

mod steps;

pub(crate) fn build_system<S: JobStore>(
    store: S,
    catalog: JobCatalog,
    owner: OwnerId,
    observer: Option<Arc<dyn bg_jobs::observer::JobObserver>>,
) -> Result<JobSystem<S>, String> {
    let mut builder = JobSystemBuilder::new(store)
        .catalog(catalog)
        .namespace(Namespace::try_new(b"bdd-jobs").map_err(|error| error.to_string())?)
        .owner(owner)
        .scheduler(common::wake_scheduler());
    if let Some(observer) = observer {
        builder = builder.with_observer(observer);
    }
    builder.build().map_err(|error| error.to_string())
}

#[derive(Default, cucumber::World)]
pub struct BddWorld {
    pub(crate) store: Option<FakeStore>,
    pub(crate) system: Option<JobSystem<FakeStore>>,
    pub(crate) job: Option<NewJob>,
    pub(crate) now: Timestamp,
    pub(crate) first_enqueue: Option<EnqueueResult>,
    pub(crate) retry_enqueue: Option<EnqueueResult>,
    pub(crate) completion: Option<CompletionDetails>,
    pub(crate) drive_report: Option<DriveReport>,
    pub(crate) audit_failed: bool,
    pub(crate) handler_calls: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    pub(crate) recovery: Option<RecoveryEvidence>,
    pub(crate) fairness: Option<FairnessEvidence>,
    pub(crate) wake: Option<WakeEvidence>,
    pub(crate) observed_events: Option<std::sync::Arc<std::sync::Mutex<Vec<JobEvent>>>>,
    pub(crate) observed_errors: Option<std::sync::Arc<std::sync::Mutex<Vec<SafeJobErrorEvent>>>>,
}

#[derive(Default)]
pub(crate) struct RecoveryEvidence {
    pub(crate) authoritative_claim: Option<TransitionAuthority>,
    pub(crate) stored_authority: Option<TransitionAuthority>,
    pub(crate) contender_conflicted: bool,
    pub(crate) stale_mutations_rejected: bool,
    pub(crate) successor_unchanged: bool,
    pub(crate) network_policy: bool,
    pub(crate) execution_ids: Vec<ExecutionId>,
    pub(crate) attempt_ids: Vec<AttemptId>,
    pub(crate) poison_dead_lettered: bool,
    pub(crate) unrelated_completed: bool,
    pub(crate) completion_reconciled: bool,
    pub(crate) redrive_reuse: Option<RedriveResult>,
    pub(crate) redrive_rotation: Option<RedriveResult>,
    pub(crate) redrive_reuse_before: Option<(ExecutionId, u32)>,
    pub(crate) redrive_rotation_before: Option<(ExecutionId, u32)>,
    pub(crate) safe_telemetry: bool,
    pub(crate) panic_retried: bool,
    pub(crate) panic_peer_completed: bool,
    pub(crate) identity_isolated: bool,
    pub(crate) cancellation_requested: bool,
    pub(crate) cancellation_terminal: bool,
    pub(crate) cancellation_authority_rejected: bool,
}

#[derive(Default)]
pub(crate) struct FairnessEvidence {
    pub(crate) selected: Vec<JobId>,
    pub(crate) fairness_bound: Option<u64>,
    pub(crate) batch: Option<Batch>,
    pub(crate) batch_application: Option<BatchApplication>,
    pub(crate) low_volume_error: Option<String>,
    pub(crate) low_volume_registered: bool,
    pub(crate) low_volume_rejection: Option<FairnessRejection>,
    pub(crate) scratch_capacity_before_shrink: Option<usize>,
    pub(crate) scratch_capacity_after_shrink: Option<usize>,
    pub(crate) scratch_len_after_clear: Option<usize>,
    pub(crate) low_volume_store_empty: bool,
    pub(crate) cross_node_conflict: bool,
}

#[derive(Debug, Default)]
pub(crate) struct WakeEvidence {
    pub(crate) expression: Option<String>,
    pub(crate) invalid_expressions: Vec<String>,
    pub(crate) deterministic_intended: Option<Timestamp>,
    pub(crate) deterministic_ids_match: bool,
    pub(crate) deterministic_enqueued: usize,
    pub(crate) cron_rejections: usize,
    pub(crate) cron_state_unchanged: bool,
    pub(crate) misfire_counts: Option<(usize, u32, usize, u32, usize, u32)>,
    pub(crate) merged_wake: Option<WakeHint>,
    pub(crate) wake_claims: u32,
    pub(crate) wake_completions: u32,
    pub(crate) wake_handler_calls: usize,
    pub(crate) wake_snapshot_empty: bool,
    pub(crate) pulse_drives: usize,
    pub(crate) pulse_stop: Option<ActivePulseStopReason>,
    pub(crate) pulse_handler_calls: usize,
    pub(crate) pulse_invocations: usize,
    pub(crate) pulse_first_has_immediate: bool,
    pub(crate) pulse_first_wake: Option<WakeHint>,
    pub(crate) pulse_first_stop: Option<DriveStopReason>,
    pub(crate) deadline_succeeded: u32,
    pub(crate) deadline_remaining_claimed: u32,
    pub(crate) deadline_stop: Option<DriveStopReason>,
    pub(crate) deadline_wake: Option<WakeHint>,
    pub(crate) already_expired_claimed: u32,
    pub(crate) already_expired_handler_calls: usize,
    pub(crate) already_expired_stop: Option<DriveStopReason>,
    pub(crate) control_applied: bool,
    pub(crate) control_conflict: bool,
    pub(crate) control_resumed: bool,
    pub(crate) cancelled: bool,
    pub(crate) peer_succeeded: u32,
    pub(crate) peer_handler_calls: usize,
}

impl fmt::Debug for BddWorld {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("BddWorld").finish_non_exhaustive()
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};

    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn main() {
    block_on(
        BddWorld::cucumber()
            .fail_on_skipped()
            .run_and_exit("tests/features"),
    );
}
