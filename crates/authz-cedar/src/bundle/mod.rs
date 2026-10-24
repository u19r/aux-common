mod bundle_compiler;
mod constants;
mod slices;
mod validation;

pub use bundle_compiler::{CompiledBundle, compile_policy_bundle, configuration_fingerprint};
#[cfg(test)]
pub(crate) use constants::GENERATED_POLICY_MAX_DEREF_LEVEL;
pub use constants::{
    BUNDLE_MANIFEST_MAX_BYTES, BUNDLE_POLICY_MAX_BYTES, BUNDLE_SCHEMA_MAX_BYTES, MAX_POLICY_SLICES,
    MAX_SCHEMA_SLICES, SLICE_SOFT_MAX_BYTES,
};
pub(crate) use slices::sha256_hex;
pub use slices::{BundleManifest, PolicySlice, SchemaSlice, SliceMeta, enforce_size};
pub(crate) use validation::validate_compiled_slices;
#[cfg(test)]
pub(crate) use validation::validate_policy_set;

#[cfg(test)]
mod bundle_compiler_tests;
#[cfg(test)]
mod test_support;

#[cfg(test)]
pub(crate) use test_support::permanent_assignment_policy;
