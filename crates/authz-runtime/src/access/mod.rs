mod role_assignment;
mod scope;

pub use role_assignment::EffectiveRoleAssignment;
pub use scope::{ScopeKind, classify_scope, role_assignment_covers_resource};

#[cfg(test)]
mod role_assignment_tests;
#[cfg(test)]
mod scope_tests;
