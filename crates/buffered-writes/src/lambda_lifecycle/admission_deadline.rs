use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::{Deadline, LifecycleError};

/// An absolute kernel monotonic deadline. Function and extension processes
/// share one host/time namespace, so queueing cannot renew the caller's budget.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub(super) struct AdmissionDeadline {
    expires_ns: u64,
}

impl AdmissionDeadline {
    pub(super) fn capture(deadline: Deadline) -> Result<Self, LifecycleError> {
        let anchor = Instant::now();
        let remaining = deadline.remaining_at(anchor);
        let now = monotonic_ns()?;
        let remaining = remaining.saturating_sub(anchor.elapsed());
        let nanos = u64::try_from(remaining.as_nanos()).unwrap_or(u64::MAX);
        Ok(Self {
            expires_ns: now.saturating_add(nanos),
        })
    }

    pub(super) fn shorten(self, deadline: Deadline) -> Result<Deadline, LifecycleError> {
        let anchor = Instant::now();
        let remaining = Duration::from_nanos(self.expires_ns.saturating_sub(monotonic_ns()?));
        Ok(deadline.shorten_to(Deadline::from_anchor(anchor, remaining), anchor))
    }
}

fn monotonic_ns() -> Result<u64, LifecycleError> {
    #[cfg(unix)]
    {
        let time = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        u64::try_from(time.tv_sec)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|nanos| nanos.checked_add(u64::try_from(time.tv_nsec).ok()?))
            .ok_or(LifecycleError::InvalidConfiguration {
                reason: "Lambda monotonic clock is outside the IPC range",
            })
    }
    #[cfg(not(unix))]
    Err(LifecycleError::InvalidConfiguration {
        reason: "Lambda IPC requires a Unix monotonic clock",
    })
}
