use std::{sync::Arc, time::Duration};

pub use bg_jobs::test_support::TestProfile;
use bg_jobs::{
    DriveBudget, JobCatalog, JobStore, Timestamp, runtime::MonotonicDeadline,
    test_support::raw::DriveRequest,
};

pub use crate::{clock::JobClock, runtime::JobRuntimeBuilder};

/// Starts a deterministic runtime composition builder for tests and
/// conformance harnesses. Production callers should use the runtime's local
/// or distributed constructors.
pub fn runtime_builder<S: JobStore>(
    store: S,
    catalog: JobCatalog,
    budget: DriveBudget,
) -> JobRuntimeBuilder<S> {
    crate::runtime::JobRuntime::builder(store, catalog, budget)
}

/// Returns a fresh clock fixed at the zero origin for tests that only need a
/// stable timestamp and do not need to advance time.
pub fn deterministic_clock() -> Arc<dyn JobClock> {
    Arc::new(TestClock::new(Timestamp::ZERO, MonotonicDeadline::ZERO))
}

/// Builds a drive request for a test-owned raw system while keeping
/// monotonic deadline arithmetic at the Tokio test-support boundary.
pub fn drive_request(
    budget: &DriveBudget,
    clock: &dyn JobClock,
) -> Result<DriveRequest, bg_jobs::ValidationError> {
    budget.request_at(clock.monotonic_now())
}

/// A clonable virtual clock for deterministic runtime tests.
///
/// The clock never reads the host wall clock. Tests advance it explicitly and
/// use [`TestProfile`] as the matching wake scheduler.
#[derive(Clone, Debug)]
pub struct TestClock {
    state: Arc<std::sync::Mutex<State>>,
}

#[derive(Debug)]
struct State {
    wall: Timestamp,
    monotonic: MonotonicDeadline,
}

impl TestClock {
    /// Creates a virtual clock at the supplied wall and monotonic values.
    pub fn new(wall: Timestamp, monotonic: MonotonicDeadline) -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(State { wall, monotonic })),
        }
    }

    /// Replaces both virtual clock values atomically.
    pub fn set(&self, wall: Timestamp, monotonic: MonotonicDeadline) {
        if let Ok(mut state) = self.state.lock() {
            state.wall = wall;
            state.monotonic = monotonic;
        }
    }

    /// Advances both clocks by the same explicit duration.
    pub fn advance(&self, duration: Duration) {
        if let Ok(mut state) = self.state.lock() {
            state.wall = state
                .wall
                .checked_add(duration)
                .unwrap_or(Timestamp::from_millis(i64::MAX));
            let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
            state.monotonic =
                MonotonicDeadline::from_nanos(state.monotonic.as_nanos().saturating_add(nanos));
        }
    }
}

impl JobClock for TestClock {
    fn wall_now(&self) -> Timestamp {
        self.state
            .lock()
            .map(|state| state.wall)
            .unwrap_or(Timestamp::from_millis(i64::MAX))
    }

    fn monotonic_now(&self) -> MonotonicDeadline {
        self.state
            .lock()
            .map(|state| state.monotonic)
            .unwrap_or(MonotonicDeadline::from_nanos(u64::MAX))
    }
}
