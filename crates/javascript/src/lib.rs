//! Explicit-input, synchronous JavaScript execution in a fresh embedded Wasm
//! instance. See the crate README for limits, permitted capabilities and caller
//! responsibilities.
#![deny(unsafe_code)]
#![cfg_attr(feature = "runtime", doc = include_str!("../README.md"))]

mod bounded_writer;
#[cfg(feature = "runtime")]
mod cancellation;
pub mod constants;
mod error;
#[cfg(feature = "runtime")]
mod executor;
mod invocation;
pub mod protocol;

#[cfg(feature = "runtime")]
pub use cancellation::JsCancellation;
pub use error::JsError;
#[cfg(feature = "runtime")]
pub use executor::JsExecutor;
pub use invocation::{JsBinding, JsInvocationInput, JsSourceOrder};
#[cfg(feature = "runtime")]
pub use invocation::{JsInvocation, JsJob};

#[cfg(all(test, feature = "runtime"))]
mod invocation_tests;
#[cfg(all(test, feature = "runtime"))]
#[cfg(test)]
mod protocol_tests;
