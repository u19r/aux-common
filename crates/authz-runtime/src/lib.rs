//! Storage-free authorization evaluation runtime.
//!
//! This crate owns the public, customer-readable hot-path evaluator shared by
//! AuxFn and aux-sidecar. Callers supply already-fetched policy and access
//! snapshots; this crate does not fetch storage, validate service tokens, or
//! know private AuxFn row formats.

mod access;
mod enrichment;
mod error;
mod evaluation;
mod local;
mod step_up;

pub use access::{
    EffectiveRoleAssignment, ScopeKind, classify_scope, role_assignment_covers_resource,
};
pub use enrichment::{
    EnrichedCedarRequest, ParentRef, ResourceAccessSnapshot, SnapshotFreshnessPolicy,
    SubjectAccessSnapshot, SubjectParentTemplate, build_subject_parent_template,
    enrich_request_with_snapshots, enrich_request_with_snapshots_at,
};
pub use error::{AuthzRuntimeError, AuthzRuntimeResult};
pub use evaluation::{
    ActionMasks, EvaluationRuntime, PermissionBits, ResolvedPermissionBits, RoleBits,
    ScopedPermissionBits,
};
pub use local::{
    ActionPolicyDecision, LocalAuthzEvaluator, LocalBatchEvaluationInput, LocalEvaluationInput,
    TrustedAuthorizationContext, action_policy_decision_bits, best_permission_for_action_with_bits,
    permissions_for_request_bits,
};
pub use step_up::{StepUpEvaluator, StepUpResult};
