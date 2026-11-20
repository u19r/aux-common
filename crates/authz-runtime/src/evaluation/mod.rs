mod constants;
mod evaluation_runtime;

pub(crate) use evaluation_runtime::CompiledActionDescriptor;
pub use evaluation_runtime::{
    ActionMasks, EvaluationRuntime, PermissionBits, ResolvedPermissionBits, RoleBits,
    ScopedPermissionBits,
};

/// Whole Unix seconds, rounded down for instants before the epoch.
pub(crate) fn epoch_seconds(timestamp: jiff::Timestamp) -> i64 {
    timestamp.as_second() - i64::from(timestamp.subsec_nanosecond() < 0)
}

#[cfg(test)]
mod evaluation_runtime_tests;
