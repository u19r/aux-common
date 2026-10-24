use super::{
    module::{compile_module, embedded_module},
    test_support::hostile_engine,
};
use crate::JsError;

fn allowed_module() -> String {
    r#"(module
      (import "wasi_snapshot_preview1" "environ_sizes_get" (func (param i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "environ_get" (func (param i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "random_get" (func (param i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "clock_time_get" (func (param i32 i64 i32)(result i32)))
      (import "wasi_snapshot_preview1" "fd_fdstat_get" (func (param i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "fd_close" (func (param i32)(result i32)))
      (import "wasi_snapshot_preview1" "fd_prestat_get" (func (param i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "fd_prestat_dir_name" (func (param i32 i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "fd_seek" (func (param i32 i64 i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "fd_read" (func (param i32 i32 i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "proc_exit" (func (param i32)))
      (memory (export "memory") 1) (table 1 funcref)
      (func $start (export "_start")) (func (export "__main_void") (result i32) i32.const 0))"#
        .into()
}
#[test]
fn given_embedded_and_contract_modules_when_initializing_then_exact_policy_passes() {
    assert!(embedded_module(hostile_engine()).is_ok());
    assert!(compile_module(hostile_engine(), &wat::parse_str(allowed_module()).unwrap()).is_ok());
}
#[test]
fn given_unauthorized_imports_signatures_exports_or_declarations_when_loading_then_unavailable() {
    let valid = allowed_module();
    let mutations = [
        valid.replace("random_get", "path_open"),
        valid.replace("random_get", "sock_open"),
        valid.replace("random_get", "poll_oneoff"),
        valid.replace("random_get", "args_get"),
        valid.replace("random_get", "get_secret"),
        valid.replace("wasi_snapshot_preview1", "env"),
        valid.replace("environ_get", "environ_sizes_get"),
        valid.replace("(param i32 i64 i32)", "(param i32 i32 i32)"),
        valid.replace("(param i32)))", "(param i32)(result i32)))"),
        valid.replace(
            "(memory (export \"memory\") 1)",
            "(import \"env\" \"memory\" (memory 1))",
        ),
        valid.replace(
            "(memory (export \"memory\") 1)",
            "(memory (export \"memory\") 1 256 shared)",
        ),
        valid.replace(
            "(memory (export \"memory\") 1)",
            "(memory (export \"memory\") i64 1)",
        ),
        valid.replace(
            "(memory (export \"memory\") 1)",
            "(memory (export \"memory\") 257)",
        ),
        valid.replace(
            "(memory (export \"memory\") 1)",
            "(memory (export \"memory\") 1 257)",
        ),
        valid.replace("(table 1 funcref)", "(table 4097 funcref)"),
        valid.replace("(table 1 funcref)", "(table 1 externref)"),
        valid.replace("(table 1 funcref)", "(table 1 4097 funcref)"),
        valid.replace("(table 1 funcref)", "(table 1 funcref)(table 1 funcref)"),
        valid.replace("(table 1 funcref)", ""),
        valid.replace("(table 1 funcref)", "(table 1 funcref)(memory 1)"),
        valid.replace("(table 1 funcref)", "(table (export \"table\") 1 funcref)"),
        valid.replace("(func $start", "(start $start)(func $start"),
        valid.replace("__main_void", "unexpected"),
        valid.replace("(export \"_start\")", "(export \"_start\") (param i32)"),
    ];
    for mutation in mutations {
        let wasm = wat::parse_str(&mutation).unwrap();
        assert!(
            matches!(
                compile_module(hostile_engine(), &wasm),
                Err(JsError::Unavailable)
            ),
            "{mutation}"
        );
    }
    assert!(matches!(
        compile_module(hostile_engine(), b"garbage"),
        Err(JsError::Unavailable)
    ));
}

#[test]
fn given_precompiled_guest_when_engine_omits_fuel_instrumentation_then_loading_is_rejected() {
    let mut config = wasmtime::Config::new();
    config.epoch_interruption(true);
    let engine = wasmtime::Engine::new(&config).expect("engine without fuel");
    assert!(matches!(
        embedded_module(&engine),
        Err(JsError::Unavailable)
    ));
}
