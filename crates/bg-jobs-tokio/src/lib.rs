//! Tokio scheduling adapter for the runtime-neutral `bg-jobs` engine.
#![deny(unsafe_code)]

mod clock;
mod constants;
mod lease_heartbeat;
#[cfg(test)]
mod lease_heartbeat_tests;
mod queue_consumer;
#[cfg(test)]
mod queue_consumer_tests;
mod queue_worker;
mod runtime;
#[cfg(test)]
mod runtime_tests;
mod scheduler;
#[cfg(test)]
mod scheduler_tests;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
#[cfg(test)]
mod test_support_tests;

pub use lease_heartbeat::LeaseHeartbeat;
pub use queue_consumer::QueueConsumer;
pub use queue_worker::{QueueOutcome, QueueWorker};
pub use runtime::{JobRuntime, JobRuntimeBuildError, JobRuntimeBuilder, WaitOutcome};
