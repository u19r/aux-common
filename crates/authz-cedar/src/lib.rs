//! Cedar policy engine integration for the authz subsystem.
//!
//! Prefer the `*_with_trusted_parents*` preparation and
//! `validate_bundle_for_config` entry points: untrusted preparation paths and
//! raw `evaluate_*_with_policy_sets` helpers bypass snapshot and parent trust
//! checks and must only back the verified hot path.
//!
//! This crate provides:
//! - Schema generation from ValidatedConfigurationModel
//! - Policy generation from roles and permissions
//! - Policy bundle compilation
//! - Cedar evaluation wrapper

mod bundle;
mod error;
mod evaluation;
mod policy;
mod schema;

pub use bundle::{
    BUNDLE_MANIFEST_MAX_BYTES, BUNDLE_POLICY_MAX_BYTES, BUNDLE_SCHEMA_MAX_BYTES, BundleManifest,
    CompiledBundle, MAX_POLICY_SLICES, MAX_SCHEMA_SLICES, PolicySlice, SLICE_SOFT_MAX_BYTES,
    SchemaSlice, SliceMeta, compile_policy_bundle, configuration_fingerprint, enforce_size,
};
pub use error::CedarError;
pub use evaluation::{
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
pub use policy::{generate_static_policies, generate_static_policies_for_resource};
pub use schema::{
    generate_base_schema, generate_schema, generate_schema_for_resource, to_pascal_case,
};
