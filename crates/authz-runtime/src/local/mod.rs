mod local_evaluator;

pub use local_evaluator::{
    ActionPolicyDecision, LocalAuthzEvaluator, LocalBatchEvaluationInput, LocalEvaluationInput,
    TrustedAuthorizationContext, action_policy_decision_bits, best_permission_for_action_with_bits,
    permissions_for_request_bits,
};
#[cfg(test)]
pub(crate) use local_evaluator::{
    build_cedar_internal_context_at, build_internal_context_at,
    compiled_action_resolution_for_profile, inject_internal_context,
    legacy_action_resolution_for_profile, record_cedar_diagnostics,
};

#[cfg(test)]
mod local_evaluator_tests;
