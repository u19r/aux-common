use std::ops::Range;

use wasmtime::{Caller, Memory};

use super::state::JobState;
use crate::JsError;

pub(super) fn guest_memory(caller: &mut Caller<'_, JobState>) -> wasmtime::Result<Memory> {
    caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| JsError::Unavailable.into())
}
pub(super) fn checked_range(
    pointer: i32,
    length: usize,
    size: usize,
) -> wasmtime::Result<Range<usize>> {
    let start = usize::try_from(pointer).map_err(|_| JsError::Unavailable)?;
    let end = start
        .checked_add(length)
        .filter(|end| *end <= size)
        .ok_or(JsError::Unavailable)?;
    Ok(start..end)
}
pub(super) fn write_bytes(
    caller: &mut Caller<'_, JobState>,
    pointer: i32,
    bytes: &[u8],
) -> wasmtime::Result<()> {
    let memory = guest_memory(caller)?;
    let range = checked_range(pointer, bytes.len(), memory.data_size(&*caller))?;
    memory
        .write(caller, range.start, bytes)
        .map_err(|_| JsError::Unavailable.into())
}
