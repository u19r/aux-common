use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};

use crate::{CedarError, PolicySlice, SchemaSlice};

pub(crate) const GENERATED_POLICY_MAX_DEREF_LEVEL: u32 = 1;

pub(crate) fn validate_compiled_slices(
    schema_slices: &[SchemaSlice],
    policy_slices: &[PolicySlice],
) -> Result<(), CedarError> {
    for schema_slice in schema_slices {
        let mut policy_set = PolicySet::new();
        for policy_slice in policy_slices
            .iter()
            .filter(|slice| slice.resource_type == schema_slice.resource_type)
        {
            let slice = PolicySet::from_json_str(&policy_slice.policies_json).map_err(|error| {
                CedarError::bundle_compilation(format!(
                    "invalid policy slice for {}: {error}",
                    schema_slice.resource_type
                ))
            })?;
            policy_set.merge(&slice, false).map_err(|error| {
                CedarError::bundle_compilation(format!(
                    "cannot merge policy slice for {}: {error}",
                    schema_slice.resource_type
                ))
            })?;
        }
        validate_policy_set(
            &schema_slice.schema_json,
            &policy_set,
            GENERATED_POLICY_MAX_DEREF_LEVEL,
        )?;
    }
    Ok(())
}

pub(crate) fn validate_policy_set(
    schema_json: &str,
    policy_set: &PolicySet,
    max_deref_level: u32,
) -> Result<(), CedarError> {
    let schema = Schema::from_json_str(schema_json).map_err(|error| {
        CedarError::bundle_compilation(format!("invalid Cedar schema: {error}"))
    })?;
    let result = Validator::new(schema).validate_with_level(
        policy_set,
        ValidationMode::Strict,
        max_deref_level,
    );
    if result.validation_passed_without_warnings() {
        return Ok(());
    }

    let errors = result
        .validation_errors()
        .map(ToString::to_string)
        .chain(result.validation_warnings().map(ToString::to_string))
        .collect::<Vec<_>>()
        .join("; ");
    Err(CedarError::bundle_compilation(format!(
        "Cedar strict validation failed at maximum dereference level {max_deref_level}: {errors}"
    )))
}
