use alloc_counter::count_allocations;

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
#[count_allocations(label = "macro_smoke")]
fn count_allocations_macro_sync_tests() {
    let values = [String::from("a"), String::from("b"), String::from("c")];
    assert_eq!(values.len(), 3);
}

#[tokio::test]
#[count_allocations(label = "macro_async_smoke")]
async fn count_allocations_macro_async_tests() {
    let values = [String::from("x"), String::from("y")];
    tokio::task::yield_now().await;
    assert_eq!(values.join(""), "xy");
}
