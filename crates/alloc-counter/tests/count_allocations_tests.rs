use std::{
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use alloc_counter::count_allocations;

const REPORT_PATH_OVERRIDE_ENV: &str = "ALLOC_COUNTER_TEST_REPORT_PATH";

#[test]
fn allocation_guard_records_allocations_tests() {
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "allocation_guard_records_allocations_tests",
        file!(),
        line!(),
        Some("unit"),
    );
    let payload = String::from("allocation-check");
    std::hint::black_box(&payload);
    let report = guard.finish();
    drop(payload);

    assert!(report.allocation_count >= 1);
    assert!(report.allocated_bytes >= 16);

    let Some(json) = alloc_counter::report_json(&report) else {
        panic!("allocation report should serialize to JSON");
    };
    assert!(json.contains("\"allocation_count\""));
    assert!(json.contains("\"allocated_bytes\""));
    assert!(json.contains("\"label\":\"unit\""));
}

#[test]
fn allocation_guard_characterizes_process_global_background_allocations() {
    use std::{
        hint::black_box,
        sync::{Arc, Barrier},
    };

    let start_allocation = Arc::new(Barrier::new(2));
    let allocation_finished = Arc::new(Barrier::new(2));
    let worker = std::thread::spawn({
        let start_allocation = Arc::clone(&start_allocation);
        let allocation_finished = Arc::clone(&allocation_finished);
        move || {
            start_allocation.wait();
            let mut background = Vec::with_capacity(4096);
            background.push(1_u8);
            black_box(&background);
            allocation_finished.wait();
        }
    });
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "allocation_guard_characterizes_process_global_background_allocations",
        file!(),
        line!(),
        Some("global-scope-characterization"),
    );

    start_allocation.wait();
    allocation_finished.wait();
    let report = guard.finish();
    worker.join().expect("background allocation worker");

    assert!(report.allocation_count >= 1);
    assert!(report.allocated_bytes >= 4096);
}

#[test]
fn given_report_path_env_when_emit_report_then_json_line_is_appended() {
    let report_path = unique_report_path();
    let current_exe = std::env::current_exe()
        .unwrap_or_else(|error| panic!("failed to find current test executable: {error}"));
    let status = Command::new(current_exe)
        .arg("--exact")
        .arg("given_report_path_when_child_helper_runs_then_emits_json_line")
        .env(alloc_counter::REPORT_PATH_ENV, &report_path)
        .env(REPORT_PATH_OVERRIDE_ENV, &report_path)
        .status()
        .unwrap_or_else(|error| panic!("failed to run helper test process: {error}"));

    assert!(status.success());

    let written = std::fs::read_to_string(&report_path).unwrap_or_else(|error| {
        panic!(
            "failed to read report output {}: {error}",
            report_path.display()
        )
    });
    let parsed = written
        .lines()
        .next()
        .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .unwrap_or_else(|| panic!("failed to parse report output {}", report_path.display()));

    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["event"], "allocation_report");
    assert_eq!(parsed["label"], "jsonl");
    assert_eq!(
        parsed["test_name"],
        "given_report_path_when_child_helper_runs_then_emits_json_line"
    );

    let _ = std::fs::remove_file(report_path);
}

#[test]
fn given_report_path_when_child_helper_runs_then_emits_json_line() {
    let Some(report_path) = std::env::var_os(REPORT_PATH_OVERRIDE_ENV) else {
        return;
    };

    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "given_report_path_when_child_helper_runs_then_emits_json_line",
        file!(),
        line!(),
        Some("jsonl"),
    );
    let payload = String::from("allocation-check");
    std::hint::black_box(&payload);
    let report = guard.finish();
    drop(payload);

    alloc_counter::emit_report(&report);

    let exists = std::fs::metadata(PathBuf::from(report_path)).is_ok();
    assert!(exists);
}

#[test]
#[count_allocations(label = "macro_smoke")]
fn count_allocations_macro_sync_tests() {
    let values = [String::from("a"), String::from("b"), String::from("c")];
    std::hint::black_box(&values);
    assert_eq!(values.len(), 3);
}

#[count_allocations]
fn count_allocations_macro_sync_return_tests() -> usize {
    7
}

#[test]
fn count_allocations_macro_preserves_sync_return_tests() {
    assert_eq!(count_allocations_macro_sync_return_tests(), 7);
}

#[count_allocations(label = "macro_async_smoke")]
#[tokio::test]
async fn count_allocations_macro_async_tests() {
    let values = [String::from("x"), String::from("y")];
    tokio::task::yield_now().await;
    assert_eq!(values.join(""), "xy");
}

#[count_allocations(label = "macro_async_return")]
async fn count_allocations_macro_async_return_tests() -> usize {
    11
}

#[tokio::test]
async fn count_allocations_macro_preserves_async_return_tests() {
    assert_eq!(count_allocations_macro_async_return_tests().await, 11);
}

fn unique_report_path() -> PathBuf {
    let nanos_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!(
        "alloc-counter-report-{}-{nanos_since_epoch}.jsonl",
        std::process::id()
    ))
}
