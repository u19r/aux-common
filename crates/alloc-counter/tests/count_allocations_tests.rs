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
