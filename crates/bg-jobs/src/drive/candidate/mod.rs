//! Candidate prechecks, durable claims, and handler execution.

mod checkpoint;
#[cfg(test)]
mod checkpoint_tests;
mod handler;
mod observation;
mod runner;
#[cfg(test)]
mod runner_tests;

pub(crate) use handler::{HandlerContext, HandlerExecution, HandlerInvocation, execute_handler};
pub(in crate::drive) use runner::{
    Candidate, CandidateResult, apply_candidate_result, process_candidate,
};
