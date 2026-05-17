//! Internal optimization-loop instrumentation probe.
//!
//! This crate is dev/diagnostic tooling, not a supported downstream API.
#![doc(hidden)]

mod constants;
mod probe;

#[cfg(test)]
mod probe_tests;

pub use crate::probe::*;
