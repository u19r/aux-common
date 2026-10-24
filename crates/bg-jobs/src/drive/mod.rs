//! Bounded, fair job driving and its subsystem module wiring.

mod candidate;
mod constants;
#[cfg(test)]
mod constants_tests;
mod discovery;
#[cfg(all(test, not(target_family = "wasm")))]
mod fair_dispatch;
#[cfg(test)]
mod fair_dispatch_tests;
mod runner;
mod scheduler;

pub(crate) use candidate::{HandlerContext, HandlerExecution, HandlerInvocation, execute_handler};
#[cfg(test)]
pub(crate) use constants::initial_completion_capacity;
#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) use fair_dispatch::{
    FairDispatchCandidateSpec, fair_dispatch_batch_item, fair_dispatch_batch_start,
    fair_dispatch_configure, fair_dispatch_hol_escape, fair_dispatch_low_volume,
    fair_dispatch_release, fair_dispatch_scratch, fair_dispatch_select, fair_dispatch_service,
};
pub(in crate::drive) use runner::claim_deadline_reached;
pub(crate) use runner::drive;
pub(crate) use scheduler::DriveClock;
#[cfg(test)]
pub(crate) use scheduler::apply_buffered_results_for_test;
