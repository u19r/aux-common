use std::{
    collections::HashMap,
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicI64, AtomicU64, AtomicUsize},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    constants::{
        MAX_BACKTRACE_BYTES, MAX_HOTSPOT_FILE_BYTES, MAX_HOTSPOTS, MAX_OPERATION_BYTES,
        MAX_SAMPLE_FILE_BYTES,
    },
    probe::{
        ProbeConfig, ProbeSample, ProbeState, estimate_json_bytes, load_hotspots_if_present,
        load_sample_if_present, sanitize_path_component, with_probe_guard,
    },
};

fn unique_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!("opt-loop-probe-{name}-{nanos}.json"))
}

fn probe_state(sample_file: PathBuf, hotspot_file: PathBuf) -> ProbeState {
    ProbeState {
        config: ProbeConfig {
            target_id: "target".to_string(),
            phase: "phase".to_string(),
            sample_index: 7,
            sample_file,
            hotspot_file,
            alloc_sample_rate: 2,
            stack_depth: 4,
        },
        alloc_count: AtomicU64::new(0),
        alloc_bytes: AtomicU64::new(0),
        live_bytes: AtomicI64::new(0),
        peak_live_bytes: AtomicU64::new(0),
        manager_wall_time_ms: AtomicU64::new(0),
        manager_alloc_count: AtomicU64::new(0),
        manager_alloc_bytes: AtomicU64::new(0),
        storage_calls: AtomicU64::new(0),
        storage_bytes: AtomicU64::new(0),
        queue_calls: AtomicU64::new(0),
        queue_bytes: AtomicU64::new(0),
        pubsub_calls: AtomicU64::new(0),
        pubsub_bytes: AtomicU64::new(0),
        bg_job_calls: AtomicU64::new(0),
        bg_job_bytes: AtomicU64::new(0),
        analytics_calls: AtomicU64::new(0),
        analytics_bytes: AtomicU64::new(0),
        hotspot_count: AtomicUsize::new(0),
        hotspots: Mutex::new(HashMap::new()),
        flush_lock: Mutex::new(()),
    }
}

#[test]
fn given_empty_probe_sample_when_checking_empty_then_ignores_identity_fields() {
    let sample = ProbeSample {
        target_id: "target".to_string(),
        phase: "phase".to_string(),
        sample_index: 3,
        timestamp_unix_ms: 123,
        process_id: 42,
        ..ProbeSample::default()
    };

    assert!(sample.is_empty());
}

#[test]
fn given_component_calls_when_snapshotting_then_external_pause_count_sums_all_components() {
    let sample_file = unique_path("component-sample");
    let hotspot_file = unique_path("component-hotspots");
    let state = probe_state(sample_file, hotspot_file);

    state.record_storage_call("put_item", 11);
    state.record_queue_call("send_message", 13);
    state.record_pubsub_call("publish", 17);
    state.record_bg_job_call("renew", 19);
    let snapshot = state.snapshot();

    assert_eq!(snapshot.storage_calls_total, 1);
    assert_eq!(snapshot.storage_bytes_total, 11);
    assert_eq!(snapshot.queue_calls_total, 1);
    assert_eq!(snapshot.pubsub_calls_total, 1);
    assert_eq!(snapshot.bg_job_calls_total, 1);
    assert_eq!(snapshot.external_pause_count_total, 4);
}

#[test]
fn given_allocations_when_recording_then_tracks_total_and_peak_live_bytes() {
    let sample_file = unique_path("alloc-sample");
    let hotspot_file = unique_path("alloc-hotspots");
    let state = probe_state(sample_file, hotspot_file);

    state.record_alloc(10);
    state.record_alloc(20);
    state.record_dealloc(15);
    state.record_realloc(5, 25);
    let snapshot = state.snapshot();

    assert_eq!(snapshot.heap_alloc_count_total, 3);
    assert_eq!(snapshot.heap_alloc_bytes_total, 55);
    assert_eq!(snapshot.heap_peak_live_bytes, 35);
}

#[test]
fn given_existing_non_empty_sample_when_flushing_empty_snapshot_then_preserves_file() {
    let sample_file = unique_path("preserve-sample");
    let hotspot_file = unique_path("preserve-hotspots");
    let state = probe_state(sample_file.clone(), hotspot_file);
    let existing = ProbeSample {
        storage_calls_total: 1,
        ..ProbeSample::default()
    };
    fs::write(
        &sample_file,
        serde_json::to_vec(&existing).expect("existing sample"),
    )
    .expect("write sample");

    state.flush();
    let loaded = load_sample_if_present(&sample_file).expect("loaded sample");

    assert_eq!(loaded.storage_calls_total, 1);
}

#[test]
fn given_hotspots_when_flushing_then_writes_records_by_count_then_bytes() {
    let sample_file = unique_path("hotspot-sample");
    let hotspot_file = unique_path("hotspot-records");
    let state = probe_state(sample_file, hotspot_file.clone());

    for bytes in [5, 7] {
        state.record_hotspot("storage", Some("put_item"), bytes);
    }
    state.flush();
    let records = load_hotspots_if_present(&hotspot_file).expect("hotspots");

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, "storage");
    assert_eq!(records[0].operation.as_deref(), Some("put_item"));
    assert_eq!(records[0].count, 2);
    assert_eq!(records[0].total_bytes, 12);
}

#[test]
fn component_calls_defer_file_io_until_explicit_flush() {
    let sample_file = unique_path("deferred-sample");
    let hotspot_file = unique_path("deferred-hotspots");
    let state = probe_state(sample_file.clone(), hotspot_file.clone());

    state.record_storage_call("put_item", 5);

    assert!(!sample_file.exists());
    assert!(!hotspot_file.exists());

    state.flush();

    assert!(sample_file.exists());
    assert!(hotspot_file.exists());
}

#[test]
fn dynamic_hotspot_operations_do_not_grow_the_thread_local_cache_without_bound() {
    let sample_file = unique_path("bounded-sample");
    let hotspot_file = unique_path("bounded-hotspots");
    let state = probe_state(sample_file, hotspot_file);

    for index in 0..=MAX_HOTSPOTS {
        let operation = format!("operation-{index}");
        state.record_hotspot("storage", Some(&operation), 1);
    }

    let hotspot_count = state.hotspots.lock().expect("hotspots").len();
    assert!(
        hotspot_count <= MAX_HOTSPOTS,
        "dynamic label cache retained {hotspot_count} entries"
    );
}

#[test]
fn diagnostic_hotspot_metadata_is_bounded_and_sensitive_labels_are_redacted() {
    let sample_file = unique_path("metadata-sample");
    let hotspot_file = unique_path("metadata-hotspots");
    let state = probe_state(sample_file, hotspot_file);
    let oversized_operation = "x".repeat(MAX_OPERATION_BYTES + 32);

    state.record_hotspot("storage", Some(&oversized_operation), 1);
    state.record_hotspot("storage", Some("authorization=Bearer secret"), 1);

    let hotspots = state.hotspot_records();
    assert!(hotspots.iter().all(|entry| {
        entry
            .operation
            .as_ref()
            .is_some_and(|operation| operation.len() <= MAX_OPERATION_BYTES)
            && entry.sample_backtrace.len() <= MAX_BACKTRACE_BYTES
    }));
    assert!(
        hotspots
            .iter()
            .any(|entry| entry.operation.as_deref() == Some("<redacted>"))
    );
    assert!(hotspots.iter().all(|entry| {
        entry
            .operation
            .as_deref()
            .is_none_or(|operation| !operation.contains("topsecret"))
    }));
}

#[test]
fn oversized_diagnostic_files_are_not_loaded() {
    let sample_file = unique_path("oversized-sample");
    let hotspot_file = unique_path("oversized-hotspots");
    fs::write(
        &sample_file,
        vec![0_u8; usize::try_from(MAX_SAMPLE_FILE_BYTES).expect("sample limit") + 1],
    )
    .expect("write oversized sample");
    fs::write(
        &hotspot_file,
        vec![0_u8; usize::try_from(MAX_HOTSPOT_FILE_BYTES).expect("hotspot limit") + 1],
    )
    .expect("write oversized hotspots");

    assert!(load_sample_if_present(&sample_file).is_none());
    assert!(load_hotspots_if_present(&hotspot_file).is_none());
}

#[test]
fn default_path_components_reject_traversal_and_are_bounded() {
    assert_eq!(sanitize_path_component("../secret", 32), ".._secret");
    assert_eq!(sanitize_path_component(".", 32), "unknown");
    assert_eq!(sanitize_path_component("..", 32), "unknown");
    assert!(
        sanitize_path_component("a/b\\c", 32)
            .chars()
            .all(|character| !matches!(character, '/' | '\\'))
    );
    assert!(sanitize_path_component(&"x".repeat(256), 8).len() <= 8);
}

#[test]
fn probe_guard_clears_thread_local_state_after_panic() {
    let result = catch_unwind(AssertUnwindSafe(|| {
        with_probe_guard(|| panic!("probe callback panic"));
    }));
    assert!(result.is_err());

    let mut entered = false;
    with_probe_guard(|| entered = true);
    assert!(entered);
}

#[test]
fn estimate_json_bytes_returns_zero_for_unserializable_values() {
    use serde::ser::{Serialize, Serializer};

    struct Broken;

    impl Serialize for Broken {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            Err(serde::ser::Error::custom("broken"))
        }
    }

    assert_eq!(estimate_json_bytes(&Broken), 0);
    assert!(estimate_json_bytes(&ProbeSample::default()) > 0);
}
