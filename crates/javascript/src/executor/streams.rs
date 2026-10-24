use std::ops::Range;

use wasmtime::Caller;

use super::{
    guest_memory::{checked_range, guest_memory, write_bytes},
    state::JobState,
};
use crate::{
    JsError,
    constants::{MAX_IOVECS, MAX_REPLY_BYTES, WASI_BADF},
};

pub(super) struct StreamRequest {
    pub(super) fd: i32,
    pub(super) pointer: i32,
    pub(super) count: i32,
    pub(super) written: i32,
}
impl StreamRequest {
    pub(super) fn read_input(self, mut caller: Caller<'_, JobState>) -> wasmtime::Result<i32> {
        let Self {
            fd,
            pointer,
            count,
            written,
        } = self;
        caller.data().check_interrupt()?;
        if fd != 0 || !caller.data().is_stream_open(fd) {
            return Ok(WASI_BADF);
        }
        let memory = guest_memory(&mut caller)?;
        let vectors = read_vectors(memory.data(&caller), pointer, count)?;
        checked_range(written, 4, memory.data_size(&caller))?;
        let (bytes, state) = memory.data_and_store_mut(&mut caller);
        let mut total = 0;
        for range in vectors {
            let length = range.len().min(state.input.len() - state.input_position);
            bytes[range.start..range.start + length]
                .copy_from_slice(&state.input[state.input_position..state.input_position + length]);
            state.input_position += length;
            total += length;
        }
        write_bytes(&mut caller, written, &(total as u32).to_le_bytes())?;
        Ok(0)
    }
    pub(super) fn write_output(self, mut caller: Caller<'_, JobState>) -> wasmtime::Result<i32> {
        let Self {
            fd,
            pointer,
            count,
            written,
        } = self;
        caller.data().check_interrupt()?;
        if !caller.data().is_stream_open(fd) || fd == 0 {
            return Ok(WASI_BADF);
        }
        if fd == 2 {
            return Err(JsError::Unavailable.into());
        }
        let memory = guest_memory(&mut caller)?;
        let vectors = read_vectors(memory.data(&caller), pointer, count)?;
        checked_range(written, 4, memory.data_size(&caller))?;
        let total: usize = vectors.iter().map(Range::len).sum();
        if total > MAX_REPLY_BYTES.saturating_sub(caller.data().output.len()) {
            return Err(JsError::OutputTooLarge.into());
        }
        let (bytes, state) = memory.data_and_store_mut(&mut caller);
        for range in vectors {
            state.output.extend_from_slice(&bytes[range]);
        }
        write_bytes(&mut caller, written, &(total as u32).to_le_bytes())?;
        Ok(0)
    }
}
fn read_vectors(bytes: &[u8], pointer: i32, count: i32) -> wasmtime::Result<Vec<Range<usize>>> {
    let count = usize::try_from(count)
        .ok()
        .filter(|n| *n <= MAX_IOVECS)
        .ok_or(JsError::Unavailable)?;
    let metadata = checked_range(pointer, count * 8, bytes.len())?;
    let mut vectors = Vec::with_capacity(count);
    for vector in bytes[metadata].as_chunks::<8>().0 {
        let pointer = i32::from_le_bytes([vector[0], vector[1], vector[2], vector[3]]);
        let length = u32::from_le_bytes([vector[4], vector[5], vector[6], vector[7]]) as usize;
        vectors.push(checked_range(pointer, length, bytes.len())?);
    }
    Ok(vectors)
}
