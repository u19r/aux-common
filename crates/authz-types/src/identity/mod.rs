mod access_assignment;
mod access_profile_session_reference;
mod constants;
mod jwt_context;
mod session_context;
mod token_context;
mod token_scope;

pub use access_assignment::{
    AccessAssignmentDurationSeconds, AccessAssignmentExplanation, AccessAssignmentMode,
    AccessAssignmentPolicy, AccessAssignmentPolicySpec, AccessAssignmentRemovalCause,
    AccessAssignmentRemovalSource, AccessAssignmentStatus, AccessAssignmentTarget,
};
pub use access_profile_session_reference::{
    AccessProfileSessionReference, AccessProfileSessionReferenceError,
};
pub use constants::{
    MAX_ACCESS_ASSIGNMENT_DURATION_SECONDS, MAX_ACCESS_ASSIGNMENT_EXPLANATION_BYTES,
    MIN_ACCESS_ASSIGNMENT_DURATION_SECONDS,
};
pub use jwt_context::{GroupMembership, JwtContext, OrgMembership, RoleAssignment, RoleScope};
pub use session_context::SessionContext;
pub use token_context::{TokenContext, TokenSubjectBinding};
pub use token_scope::{FineGrainedScopes, ResourceSelection, TokenScopeConfig, TokenScopeType};

#[cfg(test)]
mod access_assignment_tests;
#[cfg(test)]
mod access_profile_session_reference_tests;
#[cfg(test)]
mod jwt_context_tests;
#[cfg(test)]
mod session_context_tests;
#[cfg(test)]
mod token_context_tests;
#[cfg(test)]
mod token_scope_tests;
