//! Bounded compatible batch formation and per-item result application.

mod compatibility;
#[cfg(any(test, feature = "test-support"))]
mod formation;
#[cfg(any(test, feature = "test-support"))]
mod results;
#[cfg(any(test, feature = "test-support"))]
mod scratch;

#[cfg(test)]
mod formation_tests;
#[cfg(test)]
mod results_tests;

pub use compatibility::{AuthConfigId, BatchKey};
#[cfg(any(test, feature = "test-support"))]
pub use compatibility::{BatchCompatibility, BatchItem};
#[cfg(any(test, feature = "test-support"))]
pub use formation::{Batch, BatchBuilder, BatchLimits, BatchLimitsInput, BatchRejection};
#[cfg(feature = "test-support")]
pub use results::{BatchApplication, BatchItemResolution};
#[cfg(any(test, feature = "test-support"))]
pub use results::{BatchOutcome, BatchResult, BatchResultError};
#[cfg(any(test, feature = "test-support"))]
pub use scratch::ScratchStorage;
