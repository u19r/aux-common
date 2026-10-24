use wasmtime::{ResourceLimiter, StoreLimits, StoreLimitsBuilder};

use crate::{
    JsError,
    constants::{MAX_MEMORY_BYTES, MAX_TABLE_ELEMENTS},
};

pub(super) struct JobLimits {
    limits: StoreLimits,
}
impl Default for JobLimits {
    fn default() -> Self {
        Self {
            limits: StoreLimitsBuilder::new()
                .memory_size(MAX_MEMORY_BYTES)
                .table_elements(MAX_TABLE_ELEMENTS)
                .instances(1)
                .tables(1)
                .memories(1)
                .trap_on_grow_failure(true)
                .build(),
        }
    }
}
impl ResourceLimiter for JobLimits {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.limits
            .memory_growing(current, desired, maximum)
            .map_err(|_| JsError::ResourceLimit.into())
    }
    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.limits
            .table_growing(current, desired, maximum)
            .map_err(|_| JsError::ResourceLimit.into())
    }
    fn memory_grow_failed(&mut self, _: wasmtime::Error) -> wasmtime::Result<()> {
        Err(JsError::ResourceLimit.into())
    }
    fn table_grow_failed(&mut self, _: wasmtime::Error) -> wasmtime::Result<()> {
        Err(JsError::ResourceLimit.into())
    }
    fn instances(&self) -> usize {
        self.limits.instances()
    }
    fn memories(&self) -> usize {
        self.limits.memories()
    }
    fn tables(&self) -> usize {
        self.limits.tables()
    }
}
