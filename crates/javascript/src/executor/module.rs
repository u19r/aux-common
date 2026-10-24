use wasmparser::{Parser, Payload};
use wasmtime::{Config, Engine, ExternType, Module, ValType};

use crate::{
    JsError,
    constants::{MAX_MEMORY_PAGES, MAX_TABLE_ELEMENTS, MAX_WASM_STACK_BYTES, WASI_MODULE},
};

pub(super) fn create_engine() -> Result<Engine, JsError> {
    let mut config = Config::new();
    config
        .consume_fuel(true)
        .epoch_interruption(true)
        .max_wasm_stack(MAX_WASM_STACK_BYTES)
        .wasm_backtrace_max_frames(None);
    Engine::new(&config).map_err(|_| JsError::Unavailable)
}
#[expect(
    unsafe_code,
    reason = "User-approved loader for an embedded build-generated Wasm artifact"
)]
pub(super) fn embedded_module(engine: &Engine) -> Result<Module, JsError> {
    validate_declarations(include_bytes!("../../assets/quickjs.wasm"))?;
    // SAFETY: only this package's build.rs output is embedded. Wasmtime
    // produced these immutable bytes from the bundled guest for TARGET, with
    // matching fuel/epoch instrumentation and the same locked Wasmtime version.
    // Callers cannot supply bytes, paths, or cached native artifacts to this
    // function.
    let module = unsafe {
        Module::deserialize(
            engine,
            include_bytes!(concat!(env!("OUT_DIR"), "/quickjs.cwasm")),
        )
    }
    .map_err(|_| JsError::Unavailable)?;
    validate_imports(&module)?;
    validate_exports(&module)?;
    Ok(module)
}
#[cfg(test)]
pub(super) fn compile_module(engine: &Engine, bytes: &[u8]) -> Result<Module, JsError> {
    validate_declarations(bytes)?;
    let module = Module::new(engine, bytes).map_err(|_| JsError::Unavailable)?;
    validate_imports(&module)?;
    validate_exports(&module)?;
    Ok(module)
}
fn validate_declarations(bytes: &[u8]) -> Result<(), JsError> {
    let (mut memories, mut tables) = (0, 0);
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(|_| JsError::Unavailable)? {
            Payload::StartSection { .. } => return Err(JsError::Unavailable),
            Payload::MemorySection(reader) => {
                for memory in reader {
                    let m = memory.map_err(|_| JsError::Unavailable)?;
                    validate_memory(m)?;
                    memories += 1;
                }
            }
            Payload::TableSection(reader) => {
                for table in reader {
                    let t = table.map_err(|_| JsError::Unavailable)?.ty;
                    validate_table(t)?;
                    tables += 1;
                }
            }
            _ => {}
        }
    }
    if memories != 1 || tables != 1 {
        return Err(JsError::Unavailable);
    }
    Ok(())
}
fn validate_imports(module: &Module) -> Result<(), JsError> {
    let mut names = Vec::new();
    for import in module.imports() {
        let ExternType::Func(function) = import.ty() else {
            return Err(JsError::Unavailable);
        };
        let (params, results) = import_signature(import.name()).ok_or(JsError::Unavailable)?;
        if import.module() != WASI_MODULE
            || names.contains(&import.name())
            || !matches_signature(&function, params, results)
        {
            return Err(JsError::Unavailable);
        }
        names.push(import.name());
    }
    if names.len() != 12 {
        return Err(JsError::Unavailable);
    }
    Ok(())
}
fn import_signature(name: &str) -> Option<(&'static [ValType], &'static [ValType])> {
    use ValType::{I32, I64};
    match name {
        "environ_sizes_get" | "environ_get" | "random_get" | "fd_fdstat_get" | "fd_prestat_get" => {
            Some((&[I32, I32], &[I32]))
        }
        "clock_time_get" => Some((&[I32, I64, I32], &[I32])),
        "fd_close" => Some((&[I32], &[I32])),
        "fd_prestat_dir_name" => Some((&[I32, I32, I32], &[I32])),
        "fd_seek" => Some((&[I32, I64, I32, I32], &[I32])),
        "fd_read" | "fd_write" => Some((&[I32, I32, I32, I32], &[I32])),
        "proc_exit" => Some((&[I32], &[])),
        _ => None,
    }
}
fn matches_signature(
    function: &wasmtime::FuncType,
    params: &[ValType],
    results: &[ValType],
) -> bool {
    function
        .params()
        .zip(params)
        .all(|(a, b)| ValType::eq(&a, b))
        && function.params().len() == params.len()
        && function
            .results()
            .zip(results)
            .all(|(a, b)| ValType::eq(&a, b))
        && function.results().len() == results.len()
}
fn validate_exports(module: &Module) -> Result<(), JsError> {
    let mut count = 0;
    for export in module.exports() {
        let valid = match (export.name(), export.ty()) {
            ("_start", ExternType::Func(f)) => matches_signature(&f, &[], &[]),
            ("__main_void", ExternType::Func(f)) => matches_signature(&f, &[], &[ValType::I32]),
            ("memory", ExternType::Memory(_)) => true,
            _ => false,
        };
        if !valid {
            return Err(JsError::Unavailable);
        }
        count += 1;
    }
    if count != 3 {
        return Err(JsError::Unavailable);
    }
    Ok(())
}

fn validate_memory(memory: wasmparser::MemoryType) -> Result<(), JsError> {
    if memory.memory64
        || memory.shared
        || memory.page_size_log2.is_some()
        || memory.initial > MAX_MEMORY_PAGES
        || memory.maximum.is_some_and(|max| max > MAX_MEMORY_PAGES)
    {
        return Err(JsError::Unavailable);
    }
    Ok(())
}
fn validate_table(table: wasmparser::TableType) -> Result<(), JsError> {
    if table.table64
        || table.shared
        || table.initial > MAX_TABLE_ELEMENTS as u64
        || table
            .maximum
            .is_some_and(|max| max > MAX_TABLE_ELEMENTS as u64)
    {
        return Err(JsError::Unavailable);
    }
    Ok(())
}
