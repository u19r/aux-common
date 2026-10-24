use wasmtime::{Caller, Engine, Linker};

use super::{
    guest_memory::write_bytes,
    state::{GuestExit, JobState},
    streams::StreamRequest,
};
use crate::{
    JsError,
    constants::{MAX_RANDOM_BYTES, WASI_BADF, WASI_MODULE, WASI_SPIPE},
};

pub(super) fn restricted_linker(engine: &Engine) -> Result<Linker<JobState>, JsError> {
    let mut linker = Linker::new(engine);
    register_imports(&mut linker).map_err(|_| JsError::Unavailable)?;
    Ok(linker)
}
fn register_imports(linker: &mut Linker<JobState>) -> wasmtime::Result<()> {
    register_environment(linker)?;
    register_descriptors(linker)?;
    register_io(linker)
}
fn register_environment(linker: &mut Linker<JobState>) -> wasmtime::Result<()> {
    linker.func_wrap(WASI_MODULE, "environ_sizes_get", environment_sizes)?;
    linker.func_wrap(
        WASI_MODULE,
        "environ_get",
        |c: Caller<'_, JobState>, _: i32, _: i32| -> wasmtime::Result<i32> {
            c.data().check_interrupt()?;
            Ok(0)
        },
    )?;
    linker.func_wrap(WASI_MODULE, "random_get", fixed_random)?;
    linker.func_wrap(
        WASI_MODULE,
        "clock_time_get",
        |mut c: Caller<'_, JobState>, _: i32, _: i64, p: i32| -> wasmtime::Result<i32> {
            c.data().check_interrupt()?;
            write_bytes(&mut c, p, &[0; 8])?;
            Ok(0)
        },
    )?;
    Ok(())
}
fn register_descriptors(linker: &mut Linker<JobState>) -> wasmtime::Result<()> {
    linker.func_wrap(WASI_MODULE, "fd_fdstat_get", stream_status)?;
    linker.func_wrap(WASI_MODULE, "fd_close", close_stream)?;
    linker.func_wrap(
        WASI_MODULE,
        "fd_prestat_get",
        |c: Caller<'_, JobState>, _: i32, _: i32| -> wasmtime::Result<i32> {
            c.data().check_interrupt()?;
            Ok(WASI_BADF)
        },
    )?;
    linker.func_wrap(
        WASI_MODULE,
        "fd_prestat_dir_name",
        |c: Caller<'_, JobState>, _: i32, _: i32, _: i32| -> wasmtime::Result<i32> {
            c.data().check_interrupt()?;
            Ok(WASI_BADF)
        },
    )?;
    linker.func_wrap(
        WASI_MODULE,
        "fd_seek",
        |c: Caller<'_, JobState>, fd: i32, _: i64, _: i32, _: i32| -> wasmtime::Result<i32> {
            c.data().check_interrupt()?;
            Ok(if c.data().is_stream_open(fd) {
                WASI_SPIPE
            } else {
                WASI_BADF
            })
        },
    )?;
    Ok(())
}
fn register_io(linker: &mut Linker<JobState>) -> wasmtime::Result<()> {
    linker.func_wrap(
        WASI_MODULE,
        "fd_read",
        |c: Caller<'_, JobState>, fd, pointer, count, written| {
            StreamRequest {
                fd,
                pointer,
                count,
                written,
            }
            .read_input(c)
        },
    )?;
    linker.func_wrap(
        WASI_MODULE,
        "fd_write",
        |c: Caller<'_, JobState>, fd, pointer, count, written| {
            StreamRequest {
                fd,
                pointer,
                count,
                written,
            }
            .write_output(c)
        },
    )?;
    linker.func_wrap(
        WASI_MODULE,
        "proc_exit",
        |c: Caller<'_, JobState>, code: i32| -> wasmtime::Result<()> {
            c.data().check_interrupt()?;
            Err(GuestExit(code).into())
        },
    )?;
    Ok(())
}
fn environment_sizes(mut c: Caller<'_, JobState>, count: i32, bytes: i32) -> wasmtime::Result<i32> {
    c.data().check_interrupt()?;
    write_bytes(&mut c, count, &[0; 4])?;
    write_bytes(&mut c, bytes, &[0; 4])?;
    Ok(0)
}
fn fixed_random(mut c: Caller<'_, JobState>, pointer: i32, length: i32) -> wasmtime::Result<i32> {
    c.data().check_interrupt()?;
    let length = usize::try_from(length)
        .ok()
        .filter(|n| *n <= MAX_RANDOM_BYTES)
        .ok_or(JsError::Unavailable)?;
    write_bytes(&mut c, pointer, &[0; MAX_RANDOM_BYTES][..length])?;
    Ok(0)
}
fn stream_status(mut c: Caller<'_, JobState>, fd: i32, pointer: i32) -> wasmtime::Result<i32> {
    c.data().check_interrupt()?;
    if !c.data().is_stream_open(fd) {
        return Ok(WASI_BADF);
    }
    let mut bytes = [0; 24];
    bytes[0] = 2;
    let rights: u64 = if fd == 0 { 2 } else { 64 };
    bytes[8..16].copy_from_slice(&rights.to_le_bytes());
    write_bytes(&mut c, pointer, &bytes)?;
    Ok(0)
}
fn close_stream(mut c: Caller<'_, JobState>, fd: i32) -> wasmtime::Result<i32> {
    c.data().check_interrupt()?;
    if !c.data().is_stream_open(fd) {
        return Ok(WASI_BADF);
    }
    c.data_mut().closed_streams[fd as usize] = true;
    Ok(0)
}
