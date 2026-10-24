mod constants;
mod evaluator;

pub use evaluator::{
    CedarEntitiesContext, CedarEntityRef, CedarErrorDiagnostics, CedarEvaluationErrorCategory,
    CedarInternalContext, CedarRequestUids, CedarResourceScope, CedarUidRegistry, EntityParentRef,
    InternalEvaluationResult, ParsedPolicySets, PreparedCedarAction, PreparedCedarBatchFrame,
    PreparedCedarEvaluation, evaluate, evaluate_batch,
    evaluate_batch_frame_action_with_policy_sets_error_diagnostics,
    evaluate_batch_owned_with_policy_sets, evaluate_batch_with_policy_sets,
    evaluate_owned_with_policy_sets, evaluate_owned_with_trusted_parents_and_policy_sets,
    evaluate_prepared_with_policy_sets, evaluate_prepared_with_policy_sets_diagnostics,
    evaluate_prepared_with_policy_sets_error_diagnostics, evaluate_with_policy_sets,
    parse_policy_sets, prepare_batch_frame_owned_with_registry_and_trusted_internal_context,
    prepare_entities_and_context_owned, prepare_entities_and_context_owned_with_trusted_parents,
    prepare_evaluation_owned, prepare_evaluation_owned_with_registry_and_trusted_internal_context,
    prepare_evaluation_owned_with_trusted_parents,
    prepare_evaluation_owned_with_trusted_parents_and_internal_context, prepare_request_from_parts,
    prepare_request_uids, validate_bundle_for_config, validate_bundle_integrity,
};
#[cfg(test)]
pub(crate) use evaluator::{
    evaluate_prepared_with_policy_set_diagnostics,
    evaluate_prepared_with_policy_set_error_diagnostics,
};

#[cfg(test)]
mod evaluator_tests;
