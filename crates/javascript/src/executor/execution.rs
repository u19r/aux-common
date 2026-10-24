use serde::Serialize;
use serde_json::value::RawValue;
use wasmtime::{Linker, Module, Store, Trap, UpdateDeadline};

use super::{
    imports::restricted_linker,
    module::{create_engine, embedded_module},
    state::{GuestExit, JobState},
    ticker::EpochTicker,
};
use crate::{
    JsCancellation, JsError, JsInvocation, JsJob,
    constants::{JOB_FUEL, MAX_RESULT_BYTES, PROTOCOL_VERSION},
    protocol::{GuestFailure, GuestReply, GuestResult},
};

/// Reusable compiled executor. Each run owns a fresh, disposable Store and
/// instance. Callers own admission and scheduling. Construction compiles only
/// the embedded trusted module.
pub struct JsExecutor {
    module: Module,
    linker: Linker<JobState>,
    _ticker: EpochTicker,
}
impl JsExecutor {
    pub fn try_new() -> Result<Self, JsError> {
        let engine = create_engine()?;
        let module = embedded_module(&engine)?;
        let linker = restricted_linker(&engine)?;
        let ticker = EpochTicker::try_new(engine.clone())?;
        Ok(Self {
            module,
            linker,
            _ticker: ticker,
        })
    }
    /// Byte-bounded preparation; argument serialization is outside the guest
    /// deadline.
    pub fn prepare<A: Serialize>(&self, invocation: JsInvocation<'_, A>) -> Result<JsJob, JsError> {
        invocation.prepare()
    }
    /// Execute synchronously, checking cancellation and an absolute 50 ms
    /// deadline.
    pub fn run(&self, job: JsJob, cancellation: JsCancellation) -> Result<Box<RawValue>, JsError> {
        execute_module(&self.module, &self.linker, JobState::new(job, cancellation))
    }
    #[cfg(test)]
    pub(super) fn run_with_deadline(
        &self,
        job: JsJob,
        deadline: std::time::Instant,
    ) -> Result<Box<RawValue>, JsError> {
        let mut state = JobState::new(job, JsCancellation::new());
        state.deadline = deadline;
        execute_module(&self.module, &self.linker, state)
    }
}
pub(super) fn execute_module(
    module: &Module,
    linker: &Linker<JobState>,
    state: JobState,
) -> Result<Box<RawValue>, JsError> {
    let mut store = Store::new(linker.engine(), state);
    store.limiter(|state| &mut state.limits);
    store.set_fuel(JOB_FUEL).map_err(|_| JsError::Unavailable)?;
    store.set_epoch_deadline(1);
    store.epoch_deadline_callback(|store| {
        store.data().check_interrupt()?;
        Ok(UpdateDeadline::Continue(1))
    });
    store.data().check_interrupt()?;
    let result = call_guest(&mut store, module, linker);
    store.data().check_interrupt()?;
    if let Err(error) = result
        && !error
            .downcast_ref::<GuestExit>()
            .is_some_and(|exit| exit.0 == 0)
    {
        return Err(classify_trap(&error));
    }
    let reply = decode_reply(&store.data().output);
    store.data().check_interrupt()?;
    reply
}
fn call_guest(
    store: &mut Store<JobState>,
    module: &Module,
    linker: &Linker<JobState>,
) -> wasmtime::Result<()> {
    let instance = linker.instantiate(&mut *store, module)?;
    instance
        .get_typed_func::<(), ()>(&mut *store, "_start")?
        .call(store, ())
}
fn classify_trap(error: &wasmtime::Error) -> JsError {
    if let Some(error) = error.downcast_ref::<JsError>() {
        return *error;
    }
    match error.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => JsError::Timeout,
        Some(Trap::StackOverflow | Trap::MemoryOutOfBounds | Trap::TableOutOfBounds) => {
            JsError::ResourceLimit
        }
        _ => JsError::Unavailable,
    }
}
fn decode_reply(bytes: &[u8]) -> Result<Box<RawValue>, JsError> {
    let reply: GuestReply = serde_json::from_slice(bytes).map_err(|_| JsError::InvalidOutput)?;
    if reply.version != PROTOCOL_VERSION {
        return Err(JsError::InvalidOutput);
    }
    match reply.result {
        GuestResult::Success { value } if value.get().len() <= MAX_RESULT_BYTES => Ok(value),
        GuestResult::Success { .. } => Err(JsError::OutputTooLarge),
        GuestResult::Failure { code } => Err(match code {
            GuestFailure::InvalidJob => JsError::InvalidInvocation,
            GuestFailure::ScriptFailed => JsError::ScriptFailed,
            GuestFailure::InvalidOutput => JsError::InvalidOutput,
            GuestFailure::OutputTooLarge => JsError::OutputTooLarge,
        }),
    }
}
