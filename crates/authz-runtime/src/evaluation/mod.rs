mod constants;
mod evaluation_runtime;

pub(crate) use evaluation_runtime::CompiledActionDescriptor;
pub use evaluation_runtime::{
    ActionMasks, EvaluationRuntime, PermissionBits, ResolvedPermissionBits, RoleBits,
    ScopedPermissionBits,
};

#[cfg(test)]
mod evaluation_runtime_tests;
