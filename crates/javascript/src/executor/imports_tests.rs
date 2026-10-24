use super::test_support::{execute_probe, execute_wasm};
use crate::JsError;

#[test]
fn given_hostile_pointers_and_vectors_when_calling_streams_then_traps_without_panic() {
    let read = r#"(import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32)(result i32)))"#;
    for (fd, pointer, count, written) in [
        (0, -1, 1, 8),
        (0, 0, 17, 8),
        (0, 0, -1, 8),
        (0, 327677, 1, 8),
        (0, 0, 1, -1),
    ] {
        let body = format!(
            "i32.const {fd} i32.const {pointer} i32.const {count} i32.const {written} call $read \
             drop"
        );
        assert_eq!(
            execute_probe(read, "", &body).err(),
            Some(JsError::Unavailable)
        );
    }
    for (pointer, length) in [(-1, 1), (327679, 2), (16, -1), (327680, 1)] {
        let body = format!(
            "i32.const 0 i32.const {pointer} i32.store i32.const 4 i32.const {length} i32.store \
             i32.const 0 i32.const 0 i32.const 1 i32.const 8 call $read drop"
        );
        assert_eq!(
            execute_probe(read, "", &body).err(),
            Some(JsError::Unavailable)
        );
        let body = body.replace("call $read", "call $write").replace(
            "i32.const 0 i32.const 0 i32.const 1",
            "i32.const 1 i32.const 0 i32.const 1",
        );
        assert_eq!(
            execute_probe("", "", &body).err(),
            Some(JsError::Unavailable)
        );
    }
}
#[test]
fn given_overflowing_output_and_stderr_when_writing_then_fail_closed() {
    let body = "i32.const 0 i32.const 1024 i32.store i32.const 4 i32.const 262273 i32.store \
                i32.const 1 i32.const 0 i32.const 1 i32.const 8 call $write drop";
    assert_eq!(
        execute_probe("", "", body).err(),
        Some(JsError::OutputTooLarge)
    );
    let body = "i32.const 0 i32.const 1024 i32.store i32.const 4 i32.const 262200 i32.store \
                i32.const 1 i32.const 0 i32.const 1 i32.const 8 call $write drop i32.const 1 \
                i32.const 0 i32.const 1 i32.const 8 call $write drop";
    assert_eq!(
        execute_probe("", "", body).err(),
        Some(JsError::OutputTooLarge)
    );
    assert_eq!(
        execute_probe(
            "",
            "",
            "i32.const 2 i32.const 0 i32.const 0 i32.const 8 call $write drop"
        )
        .err(),
        Some(JsError::Unavailable)
    );
}
#[test]
fn given_virtual_descriptors_when_using_unknown_or_closed_streams_then_badf() {
    let imports = r#"(import "wasi_snapshot_preview1" "fd_close" (func $close (param i32)(result i32)))
      (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "fd_seek" (func $seek (param i32 i64 i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "fd_fdstat_get" (func $stat (param i32 i32)(result i32)))"#;
    let body = "i32.const 0 call $close drop i32.const 0 call $close i32.const 8 i32.ne if \
                unreachable end
        i32.const 0 i32.const 0 i32.const 0 i32.const 8 call $read i32.const 8 i32.ne if \
                unreachable end
        i32.const 4 i32.const 0 call $stat i32.const 8 i32.ne if unreachable end
        i32.const 4 i64.const 0 i32.const 0 i32.const 0 call $seek i32.const 8 i32.ne if \
                unreachable end
        i32.const 1 i64.const 0 i32.const 0 i32.const 0 call $seek i32.const 70 i32.ne if \
                unreachable end
        i32.const 9 i32.const -1 i32.const -1 i32.const -1 call $write i32.const 8 i32.ne if \
                unreachable end
        i32.const 1 i32.const 128 call $stat drop i32.const 136 i64.load i64.const 64 i64.ne if \
                unreachable end
        i32.const 144 i64.load i64.eqz if else unreachable end";
    assert_eq!(execute_probe(imports, "", body).unwrap().get(), "true");
}
#[test]
fn given_guest_io_when_reading_then_only_job_bytes_and_eof_are_available() {
    let imports = r#"(import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32)(result i32)))"#;
    let body = "i32.const 0 i32.const 256 i32.store i32.const 4 i32.const 256 i32.store
      i32.const 0 i32.const 0 i32.const 1 i32.const 8 call $read drop
      i32.const 8 i32.load i32.const 14 i32.ne if unreachable end
      i32.const 256 i32.load8_u i32.const 101 i32.ne if unreachable end
      i32.const 0 i32.const 0 i32.const 1 i32.const 8 call $read drop
      i32.const 8 i32.load i32.eqz if else unreachable end";
    assert_eq!(execute_probe(imports, "", body).unwrap().get(), "true");
}
#[test]
fn given_host_environment_clock_random_and_files_when_guest_requests_then_inert() {
    let imports = r#"(import "wasi_snapshot_preview1" "environ_sizes_get" (func $sizes (param i32 i32)(result i32)))
       (import "wasi_snapshot_preview1" "environ_get" (func $env (param i32 i32)(result i32)))
       (import "wasi_snapshot_preview1" "clock_time_get" (func $clock (param i32 i64 i32)(result i32)))
       (import "wasi_snapshot_preview1" "random_get" (func $random (param i32 i32)(result i32)))
       (import "wasi_snapshot_preview1" "fd_prestat_get" (func $prestat (param i32 i32)(result i32)))
       (import "wasi_snapshot_preview1" "fd_prestat_dir_name" (func $directory (param i32 i32 i32)(result i32)))"#;
    let body = "i32.const 128 i32.const 132 call $sizes drop i32.const 128 i64.load i64.eqz if \
                else unreachable end
       i32.const -1 i32.const -1 call $env i32.eqz if else unreachable end
       i32.const 1 i64.const 1 i32.const 128 call $clock drop i32.const 128 i64.load i64.eqz if \
                else unreachable end
       i32.const 128 i32.const 256 call $random drop i32.const 128 i64.load i64.eqz if else \
                unreachable end
       i32.const 3 i32.const 0 call $prestat i32.const 8 i32.ne if unreachable end
       i32.const 3 i32.const -1 i32.const -1 call $directory i32.const 8 i32.ne if unreachable end";
    assert_eq!(execute_probe(imports, "", body).unwrap().get(), "true");
    for body in [
        "i32.const 128 i32.const 257 call $random drop",
        "i32.const -1 i32.const 1 call $random drop",
        "i32.const 128 i32.const -1 call $random drop",
        "i32.const 0 i64.const 0 i32.const -1 call $clock drop",
    ] {
        assert_eq!(
            execute_probe(imports, "", body).err(),
            Some(JsError::Unavailable)
        );
    }
}
#[test]
fn given_memory_and_table_growth_when_exceeding_limits_then_typed_resource_limit() {
    for body in [
        "i32.const 256 memory.grow drop",
        "ref.null func i32.const 4096 table.grow drop",
        "i32.const -1 i32.load drop",
    ] {
        assert_eq!(
            execute_probe("", "", body).err(),
            Some(JsError::ResourceLimit)
        );
    }
    let oversized = wat::parse_str(
        "(module (memory (export \"memory\") 257) (func (export \"_start\")))".replace("\\", ""),
    )
    .unwrap();
    assert_eq!(execute_wasm(&oversized).err(), Some(JsError::ResourceLimit));
}
#[test]
fn given_exit_and_malformed_replies_when_guest_finishes_then_parent_stays_alive_and_rejects() {
    let imports = r#"(import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))"#;
    assert_eq!(
        execute_probe(imports, "", "i32.const 0 call $exit").err(),
        Some(JsError::InvalidOutput)
    );
    assert_eq!(
        execute_probe(imports, "", "i32.const 1 call $exit").err(),
        Some(JsError::Unavailable)
    );
    let valid_write = "i32.const 0 i32.const 1024 i32.store i32.const 4 i32.const 54 i32.store \
                       i32.const 1 i32.const 0 i32.const 1 i32.const 8 call $write drop i32.const \
                       0 call $exit";
    assert_eq!(
        execute_probe(imports, "", valid_write).unwrap().get(),
        "true"
    );
    for reply in [
        r#"{"version":2,"result":{"type":"success","value":true}}"#,
        r#"{"version":1,"result":{"type":"success","value":true,"extra":1}}"#,
        r#"{"version":1,"result":{"type":"failure","code":"customer_secret"}}"#,
        r#"{"version":1,"result":{"type":"success","value":true}} null"#,
    ] {
        let escaped = reply.replace('"', r#"\""#);
        let declaration = format!("(data (i32.const 2048) \"{escaped}\")");
        let body = format!(
            "i32.const 0 i32.const 2048 i32.store i32.const 4 i32.const {} i32.store i32.const 1 \
             i32.const 0 i32.const 1 i32.const 8 call $write drop i32.const 0 call $exit",
            reply.len()
        );
        assert_eq!(
            execute_probe(imports, &declaration, &body).err(),
            Some(JsError::InvalidOutput)
        );
    }
}

#[test]
fn given_exact_memory_and_table_ceiling_when_growing_one_more_then_denied() {
    assert_eq!(
        execute_probe(
            "",
            "",
            "i32.const 251 memory.grow i32.const 5 i32.ne if unreachable end i32.const 1 \
             memory.grow drop"
        )
        .err(),
        Some(JsError::ResourceLimit)
    );
    assert_eq!(
        execute_probe(
            "",
            "",
            "ref.null func i32.const 4095 table.grow i32.const 1 i32.ne if unreachable end \
             ref.null func i32.const 1 table.grow drop"
        )
        .err(),
        Some(JsError::ResourceLimit)
    );
}
