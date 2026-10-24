use std::{
    sync::OnceLock,
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::value::RawValue;
use wasmtime::{Engine, Module};

use super::{
    execution::execute_module, imports::restricted_linker, module::create_engine, state::JobState,
    ticker::EpochTicker,
};
use crate::{
    JsCancellation, JsError, JsExecutor, JsInvocation, JsInvocationInput, JsJob, JsSourceOrder,
};

pub(crate) fn executor() -> &'static JsExecutor {
    static EXECUTOR: OnceLock<JsExecutor> = OnceLock::new();
    EXECUTOR.get_or_init(|| JsExecutor::try_new().expect("embedded module must initialize"))
}
pub(super) fn evaluate<A: Serialize>(source: &str, arguments: A) -> Result<Box<RawValue>, JsError> {
    executor().run(prepare_apply(source, arguments)?, JsCancellation::new())
}
// Size-boundary semantics use the actual guest and every resource limit. The
// independent public-path timeout tests retain the production 50 ms deadline.
pub(super) fn evaluate_result_contract<A: Serialize>(
    source: &str,
    arguments: A,
) -> Result<Box<RawValue>, JsError> {
    let job = prepare_apply(source, arguments)?;
    executor().run_with_deadline(job, Instant::now() + Duration::from_secs(60))
}
fn prepare_apply<A: Serialize>(source: &str, arguments: A) -> Result<JsJob, JsError> {
    let invocation = JsInvocation::try_new(JsInvocationInput {
        source,
        function: "apply",
        arguments,
        bindings: &[],
        source_order: JsSourceOrder::BeforeBindings,
    })?;
    executor().prepare(invocation)
}
pub(super) fn hostile_engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| create_engine().unwrap())
}
// Test-only module acceptance bypass. All probes still use the production
// imports, Store limits, fuel, deadline, cancellation and reply validation.
pub(super) fn execute_probe(
    imports: &str,
    declarations: &str,
    body: &str,
) -> Result<Box<RawValue>, JsError> {
    let wasm = wat::parse_str(format!(r#"(module
        (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
        {imports}
        (memory (export "memory") 5) (table 1 funcref)
        (data (i32.const 1024) "{{\"version\":1,\"result\":{{\"type\":\"success\",\"value\":true}}}}")
        {declarations}
        (func (export "_start") {body}
            i32.const 0 i32.const 1024 i32.store
            i32.const 4 i32.const 54 i32.store
            i32.const 1 i32.const 0 i32.const 1 i32.const 8 call $write drop))"#)).unwrap();
    execute_wasm(&wasm)
}
pub(super) fn execute_wasm(wasm: &[u8]) -> Result<Box<RawValue>, JsError> {
    let engine = hostile_engine();
    let module = Module::new(engine, wasm).unwrap();
    let linker = restricted_linker(engine).unwrap();
    let _ticker = EpochTicker::try_new(engine.clone()).unwrap();
    execute_module(
        &module,
        &linker,
        JobState::new(
            JsJob {
                wire: b"explicit input".to_vec(),
            },
            JsCancellation::new(),
        ),
    )
}
