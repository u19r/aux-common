//! Candidate preparation, admission checks, and fair selection.

mod admission;
mod capacity;
mod preparation;
mod runner;
pub(super) mod state;

#[cfg(test)]
mod runner_tests;
#[cfg(test)]
mod state_tests;

pub(super) use runner::SelectionScore;
#[cfg(test)]
pub(super) use runner::{record_selection_scan_visit, record_selection_scope_visit};
