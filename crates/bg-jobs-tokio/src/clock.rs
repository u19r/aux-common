use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bg_jobs::{Timestamp, runtime::MonotonicDeadline};

/// Clock used by the Tokio runtime. The trait stays private; deterministic
/// implementations are exposed only through the crate's test-support feature.
pub trait JobClock: Send + Sync + 'static {
    fn wall_now(&self) -> Timestamp;
    fn monotonic_now(&self) -> MonotonicDeadline;
}

#[derive(Debug)]
struct HostClock {
    monotonic_origin: Instant,
}

impl Default for HostClock {
    fn default() -> Self {
        Self {
            monotonic_origin: Instant::now(),
        }
    }
}

impl JobClock for HostClock {
    fn wall_now(&self) -> Timestamp {
        let milliseconds = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
            Err(_) => 0,
        };
        Timestamp::from_millis(milliseconds)
    }

    fn monotonic_now(&self) -> MonotonicDeadline {
        let nanos = self.monotonic_origin.elapsed().as_nanos();
        let nanos = u64::try_from(nanos).unwrap_or(u64::MAX);
        MonotonicDeadline::from_nanos(nanos)
    }
}

pub(crate) fn system_clock() -> std::sync::Arc<dyn JobClock> {
    static HOST_CLOCK: std::sync::OnceLock<std::sync::Arc<HostClock>> = std::sync::OnceLock::new();
    HOST_CLOCK
        .get_or_init(|| std::sync::Arc::new(HostClock::default()))
        .clone()
}
