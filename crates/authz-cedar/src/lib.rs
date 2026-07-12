//! Cedar policy engine integration for the authz subsystem.
//!
//! This crate provides:
//! - Schema generation from ValidatedConfigurationModel
//! - Policy generation from roles and permissions
//! - Policy bundle compilation
//! - Cedar evaluation wrapper

mod bundle_compiler;
mod error;
mod evaluator;
mod policy_generator;
mod schema_generator;
mod slices;
mod validation;

pub use bundle_compiler::*;
pub use error::*;
pub use evaluator::*;
pub use policy_generator::*;
pub use schema_generator::*;
pub use slices::*;

#[cfg(test)]
mod bundle_compiler_tests;
#[cfg(test)]
mod evaluator_alloc_tests;
#[cfg(test)]
mod evaluator_tests;
#[cfg(test)]
mod policy_generator_integration_tests;
#[cfg(test)]
mod policy_generator_tests;
#[cfg(test)]
mod schema_generator_tests;
