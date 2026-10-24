//! Candidate scheduling, completion ordering, and shutdown control.

mod clock;
#[cfg(test)]
mod clock_tests;
mod completion;
#[cfg(test)]
mod completion_tests;
mod owner;
mod reservation;
mod runner;
mod shutdown;
#[cfg(test)]
mod shutdown_tests;

pub(crate) use clock::DriveClock;
#[cfg(test)]
pub(crate) use completion::apply_buffered_results_for_test;
pub(in crate::drive) use runner::run;
pub(in crate::drive::scheduler) use runner::{CompletedCandidate, InFlightCandidate};
