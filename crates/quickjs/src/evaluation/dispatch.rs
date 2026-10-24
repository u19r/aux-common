use std::{
    io::{Read, Write},
    process::ExitCode,
};

use javascript::{
    constants::{MAX_JOB_BYTES, PROTOCOL_VERSION},
    protocol::{GuestFailure, GuestJob, GuestReply, GuestResult},
};
use rquickjs::{Context, Runtime, context::intrinsic};

use super::{invocation, output};

pub(crate) fn run() -> ExitCode {
    let result = read_job()
        .and_then(|job| evaluate_result(&job))
        .map_or_else(
            |code| GuestResult::Failure { code },
            |value| GuestResult::Success { value },
        );
    let reply = GuestReply {
        version: PROTOCOL_VERSION,
        result,
    };
    let Ok(bytes) = reply.encode() else {
        return ExitCode::FAILURE;
    };
    if std::io::stdout().write_all(&bytes).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
fn read_job() -> Result<GuestJob, GuestFailure> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_JOB_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| GuestFailure::InvalidJob)?;
    if bytes.len() > MAX_JOB_BYTES {
        return Err(GuestFailure::InvalidJob);
    }
    let job: GuestJob = serde_json::from_slice(&bytes).map_err(|_| GuestFailure::InvalidJob)?;
    job.validate().map_err(|_| GuestFailure::InvalidJob)?;
    Ok(job)
}
fn evaluate_result(job: &GuestJob) -> Result<Box<serde_json::value::RawValue>, GuestFailure> {
    let runtime = Runtime::new().map_err(|_| GuestFailure::ScriptFailed)?;
    runtime.set_max_stack_size(crate::constants::QUICKJS_STACK_BYTES);
    let context = Context::builder()
        .with::<intrinsic::Eval>()
        .with::<intrinsic::Json>()
        .build(&runtime)
        .map_err(|_| GuestFailure::ScriptFailed)?;
    context.with(|ctx| {
        let math: rquickjs::Object = ctx
            .globals()
            .get("Math")
            .map_err(|_| GuestFailure::ScriptFailed)?;
        math.remove("random")
            .map_err(|_| GuestFailure::ScriptFailed)?;
        let value =
            invocation::invoke_function(&ctx, job).map_err(|_| GuestFailure::ScriptFailed)?;
        output::encode_result(&ctx, value)
    })
}
