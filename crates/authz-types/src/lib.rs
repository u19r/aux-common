//! Authorization types for the authz subsystem.
//!
//! This crate contains shared types used across authz crates:
//! - Configuration model types (ResourceType, Permission, Role)
//! - API evaluation types (Subject, Resource, Action, Context)
//! - Evaluation request/response types
//! - Validation errors

mod action;
mod action_pattern;
mod api_evaluation;
mod authn_provider;
mod challenge;
mod configuration_model;
mod constants;
mod context;
mod control_plane_requests;
mod default_scoping;
mod error;
mod evaluation_properties;
mod evaluation_request;
mod evaluation_response;
mod jwt_context;
mod permission;
mod resource;
mod resource_type;
mod role;
mod scope;
mod scope_mapping;
mod session_context;
mod step_up;
mod subject;
mod token_context;
mod token_scope;

pub use action::*;
pub use action_pattern::*;
pub use api_evaluation::*;
pub use authn_provider::*;
pub use challenge::*;
pub use configuration_model::*;
pub use constants::*;
pub use context::*;
pub use control_plane_requests::*;
pub use default_scoping::*;
pub use error::*;
pub use evaluation_properties::*;
pub use evaluation_request::*;
pub use evaluation_response::*;
pub use jwt_context::*;
pub use permission::*;
pub use resource::*;
pub use resource_type::*;
pub use role::*;
pub use scope::*;
pub use scope_mapping::*;
pub use session_context::*;
pub use step_up::*;
pub use subject::*;
pub use token_context::*;
pub use token_scope::*;

#[cfg(test)]
mod action_pattern_tests;
#[cfg(test)]
mod configuration_model_tests;
#[cfg(test)]
mod control_plane_requests_tests;
#[cfg(test)]
mod evaluation_properties_tests;
#[cfg(test)]
mod security_tests;
