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

pub(crate) const GENERATED_POLICY_MAX_DEREF_LEVEL: u32 = 1;
