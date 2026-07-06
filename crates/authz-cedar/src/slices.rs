use serde::{Deserialize, Serialize};

/// Soft ceiling for any persisted slice. Keep this well below backend item-size
/// limits.
pub const SLICE_SOFT_MAX_BYTES: usize = 128 * 1024;

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
    pub schema_slices: Vec<SliceMeta>,
    pub policy_slices: Vec<SliceMeta>,
    pub compiled_at_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SliceMeta {
    pub key: String,
    pub size_bytes: usize,
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
