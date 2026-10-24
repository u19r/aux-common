//! Experimental native HTTP server lifecycle for AWS Lambda Web Functions.
//!
//! Callers own application initialization, request routing, and worker duties.
//! This crate reads the reserved listen and runtime addresses and acknowledges
//! readiness. It does not read credentials or create background work.

mod constants;
mod environment;
mod error;
mod runtime;

#[cfg(test)]
mod environment_tests;
#[cfg(test)]
mod runtime_tests;

pub use environment::LambdaWebEnvironment;
pub use error::LambdaWebRuntimeError;
