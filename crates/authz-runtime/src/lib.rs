//! Storage-free authorization evaluation runtime.
//!
//! This crate owns the public, customer-readable hot-path evaluator shared by
//! AuxFn and aux-sidecar. Callers supply already-fetched policy and access
//! snapshots; this crate does not fetch storage, validate service tokens, or
//! know private AuxFn row formats.

mod enrichment;
mod error;
mod evaluation_runtime;
mod local_evaluator;
mod role_assignment;
mod scope;
mod step_up_evaluator;

pub use enrichment::{
    EnrichedCedarRequest, ParentRef, ResourceAccessSnapshot, SubjectAccessSnapshot,
    SubjectParentTemplate, build_subject_parent_template, enrich_request_with_snapshots,
};
pub use error::{AuthzRuntimeError, AuthzRuntimeResult};
pub use evaluation_runtime::{
    ActionMasks, EvaluationRuntime, PermissionBits, ResolvedPermissionBits, RoleBits,
    ScopedPermissionBits,
};
pub use local_evaluator::{
    ActionPolicyDecision, LocalAuthzEvaluator, LocalBatchEvaluationInput, LocalEvaluationInput,
    action_policy_decision_bits, best_permission_for_action_with_bits,
    permissions_for_request_bits,
};
pub use role_assignment::EffectiveRoleAssignment;
pub use scope::{ScopeKind, classify_scope, role_assignment_covers_resource};
pub use step_up_evaluator::{StepUpEvaluator, StepUpResult};

#[cfg(test)]
mod evaluation_runtime_tests;
#[cfg(test)]
mod local_evaluator_tests;
#[cfg(test)]
mod step_up_evaluator_tests;
