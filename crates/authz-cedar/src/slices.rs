use serde::{Deserialize, Serialize};

/// Soft ceiling for any persisted slice. Keep this well below backend item-size
/// limits.
pub const SLICE_SOFT_MAX_BYTES: usize = 128 * 1024;
/// Hard ceiling for the aggregate policy JSON accepted by a parsed bundle.
pub const BUNDLE_POLICY_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of policy slices accepted from an untrusted serialized
/// bundle.
pub const MAX_POLICY_SLICES: usize = 4_096;
/// Maximum number of schema slices accepted from an untrusted serialized
/// bundle.
pub const MAX_SCHEMA_SLICES: usize = 4_096;
/// Maximum aggregate schema payload accepted from an untrusted bundle.
pub const BUNDLE_SCHEMA_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Maximum aggregate manifest metadata accepted before hashing and sorting.
pub const BUNDLE_MANIFEST_MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaSlice {
    pub resource_type: String,
    pub schema_json: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySlice {
    pub resource_type: String,
    pub policies_json: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleManifest {
    pub version: u64,
    /// Fingerprint of the validated authorization configuration used to
    /// compile this bundle. `None` is retained only to decode legacy
    /// persisted manifests; those manifests must be rebuilt before use.
    #[serde(default)]
    pub config_fingerprint: Option<String>,
    /// Digest of the base Cedar schema payload.
    #[serde(default)]
    pub base_schema_sha256: Option<String>,
    pub schema_slices: Vec<SliceMeta>,
    pub policy_slices: Vec<SliceMeta>,
    pub compiled_at_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SliceMeta {
    pub key: String,
    pub size_bytes: usize,
    /// Digest of the persisted slice payload. Optional only for decoding old
    /// manifests; a bundle with missing integrity metadata is never accepted.
    #[serde(default)]
    pub sha256: Option<String>,
}

pub(crate) fn sha256_hex(payload: impl AsRef<[u8]>) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(payload.as_ref());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn enforce_size(label: &str, bytes: usize) -> Result<(), String> {
    if bytes > SLICE_SOFT_MAX_BYTES {
        Err(format!(
            "{label} exceeds soft limit {SLICE_SOFT_MAX_BYTES} bytes: {bytes}"
        ))
    } else {
        Ok(())
    }
}
