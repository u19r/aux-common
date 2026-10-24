//! Workspace-private parser support for values rendered by Quint Connect.
//!
//! This crate is a test-only dependency of the Quint connector drivers. It is
//! not part of aux-common's runtime or public production API.
#![deny(unsafe_code)]

mod parser;

#[cfg(test)]
mod parser_tests;

pub use parser::{RenderedValue, parse};
