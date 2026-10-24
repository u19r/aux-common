mod planning;
#[cfg(test)]
mod planning_tests;

#[cfg(any(test, feature = "test-support"))]
pub use planning::{WakeCandidates, WakeWatermark};
pub(crate) use planning::{WakeUpdate, apply};
