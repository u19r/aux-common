use std::{
    collections::HashMap,
    fs,
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, AtomicU64, AtomicUsize},
    },
    task::{Context, Poll, Waker},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    constants::{
        DEFAULT_ALLOC_SAMPLE_RATE, DEFAULT_STACK_DEPTH, ENV_ALLOC_SAMPLE_RATE, ENV_ENABLED,
        ENV_HOTSPOT_FILE, ENV_PHASE, ENV_SAMPLE_FILE, ENV_SAMPLE_INDEX, ENV_STACK_DEPTH,
        ENV_TARGET_ID, FLUSH_EVERY_ALLOC_EVENTS, MAX_BACKTRACE_BYTES, MAX_HOTSPOT_FILE_BYTES,
        MAX_HOTSPOTS, MAX_OPERATION_BYTES, MAX_SAMPLE_FILE_BYTES, MAX_STACK_DEPTH,
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

const DISABLED_CHILD_ENV: &str = "OPT_LOOP_PROBE_DISABLED_CHILD";
const DISABLED_HELPERS_TEST_FILTER: &str =
    "probe_tests::given_disabled_probe_when_using_public_helpers_then_operations_are_noops";

fn env_values(entries: &[(&str, &str)]) -> HashMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

#[test]
fn given_disabled_or_invalid_enablement_when_parsing_then_returns_no_probe_config() {
    // Given an absent enablement value.
    assert!(ProbeState::from_env_values(&HashMap::new()).is_none());

    // Given enablement values that are false or not recognized.
    for enabled in ["0", "false", "no", "off", "invalid"] {
        let values = env_values(&[(ENV_ENABLED, enabled)]);

        // When the environment is parsed without constructing a live state.
        let config = ProbeState::from_env_values(&values);

        // Then collection stays disabled for every non-truthy value.
        assert!(config.is_none(), "unexpected enablement: {enabled}");
    }
}

#[test]
fn given_enabled_environment_when_parsing_then_applies_defaults_without_live_io() {
    // Given only a truthy enablement value.
    let values = env_values(&[(ENV_ENABLED, "yes")]);

    // When the configuration boundary parses the values.
    let state = ProbeState::from_env_values(&values).expect("enabled configuration");
    let config = &state.config;

    // Then defaults are deterministic and no files need to be touched.
    assert_eq!(config.target_id, "unknown");
    assert_eq!(config.phase, "unknown");
    assert_eq!(config.sample_index, 0);
    assert_eq!(config.alloc_sample_rate, DEFAULT_ALLOC_SAMPLE_RATE);
    assert_eq!(config.stack_depth, DEFAULT_STACK_DEPTH);
    assert_eq!(
        config.sample_file,
        PathBuf::from("tmp/opt-loop/runs/unknown/unknown/sample-0.json")
    );
    assert_eq!(
        config.hotspot_file,
        PathBuf::from("tmp/opt-loop/runs/unknown/unknown/sample-0-hotspots.json")
    );
}

#[test]
fn given_explicit_environment_when_parsing_then_sanitizes_paths_and_clamps_limits() {
    // Given explicit identifiers, paths, a sample index, and over-limit depth.
    let stack_depth = (MAX_STACK_DEPTH + 1).to_string();
    let values = env_values(&[
        (ENV_ENABLED, "TRUE"),
        (ENV_TARGET_ID, "../Target /"),
        (ENV_PHASE, "phase\\unsafe"),
        (ENV_SAMPLE_INDEX, "17"),
        (ENV_SAMPLE_FILE, "/tmp/explicit-sample.json"),
        (ENV_HOTSPOT_FILE, "/tmp/explicit-hotspots.json"),
        (ENV_ALLOC_SAMPLE_RATE, "512"),
        (ENV_STACK_DEPTH, &stack_depth),
    ]);

    // When the configuration boundary parses the values.
    let state = ProbeState::from_env_values(&values).expect("enabled configuration");
    let config = &state.config;

    // Then identifiers are safe while explicit operator paths remain intact.
    assert_eq!(config.target_id, ".._Target__");
    assert_eq!(config.phase, "phase_unsafe");
    assert_eq!(config.sample_index, 17);
    assert_eq!(
        config.sample_file,
        PathBuf::from("/tmp/explicit-sample.json")
    );
    assert_eq!(
        config.hotspot_file,
        PathBuf::from("/tmp/explicit-hotspots.json")
    );
    assert_eq!(config.alloc_sample_rate, 512);
    assert_eq!(config.stack_depth, MAX_STACK_DEPTH);
}

#[test]
fn given_same_sample_and_hotspot_path_when_parsing_then_rejects_colliding_outputs() {
    // Given an enabled probe configured to write both schemas to one file.
    let values = env_values(&[
        (ENV_ENABLED, "1"),
        (ENV_SAMPLE_FILE, "/tmp/opt-loop-probe-colliding-output.json"),
        (
            ENV_HOTSPOT_FILE,
            "/tmp/opt-loop-probe-colliding-output.json",
        ),
    ]);

    // When the configuration boundary validates output destinations.
    let state = ProbeState::from_env_values(&values);

    // Then instrumentation is disabled rather than silently overwriting one
    // diagnostic schema with the other.
    assert!(state.is_none());
}

#[test]
fn given_invalid_numeric_environment_when_parsing_then_uses_safe_defaults() {
    // Given malformed and zero numeric values.
    let values = env_values(&[
        (ENV_ENABLED, "on"),
        (ENV_SAMPLE_INDEX, "not-a-number"),
        (ENV_ALLOC_SAMPLE_RATE, "0"),
        (ENV_STACK_DEPTH, "0"),
    ]);

    // When the configuration boundary parses the values.
    let state = ProbeState::from_env_values(&values).expect("enabled configuration");
    let config = &state.config;

    // Then invalid values fall back without touching the filesystem.
    assert_eq!(config.sample_index, 0);
    assert_eq!(config.alloc_sample_rate, DEFAULT_ALLOC_SAMPLE_RATE);
    assert_eq!(config.stack_depth, DEFAULT_STACK_DEPTH);
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
fn given_component_bytes_at_counter_limit_when_recording_more_then_totals_remain_saturated() {
    // Given a component byte counter at the largest representable value.
    let state = probe_state(
        unique_path("saturated-component-sample"),
        unique_path("saturated-component-hotspots"),
    );
    state.record_storage_call("read", u64::MAX);

    // When another component event is recorded.
    state.record_storage_call("read", 1);

    // Then diagnostics remain monotonic instead of wrapping to zero.
    assert_eq!(state.snapshot().storage_calls_total, 2);
    assert_eq!(state.snapshot().storage_bytes_total, u64::MAX);
}

#[test]
fn given_analytics_work_when_snapshotting_then_counts_bytes_and_pause_total_are_recorded() {
    // Given a state with no component activity.
    let state = probe_state(
        unique_path("analytics-sample"),
        unique_path("analytics-hotspots"),
    );

    // When analytics work is recorded.
    state.record_analytics_call("query", 23);
    let snapshot = state.snapshot();

    // Then analytics totals contribute to the external pause count.
    assert_eq!(snapshot.analytics_calls_total, 1);
    assert_eq!(snapshot.analytics_bytes_total, 23);
    assert_eq!(snapshot.external_pause_count_total, 1);
    assert_eq!(state.hotspot_records()[0].kind, "analytics");
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
fn given_allocation_flush_boundary_when_recording_then_persists_bounded_sample() {
    // Given a state configured to sample only at the flush boundary.
    let sample_file = unique_path("alloc-boundary-sample");
    let hotspot_file = unique_path("alloc-boundary-hotspots");
    let mut state = probe_state(sample_file.clone(), hotspot_file);
    state.config.alloc_sample_rate = FLUSH_EVERY_ALLOC_EVENTS;

    // When exactly one flush interval of allocations is recorded.
    for _ in 0..FLUSH_EVERY_ALLOC_EVENTS {
        state.record_alloc(1);
    }

    // Then the boundary flush writes the complete bounded sample and one
    // bounded hotspot.
    let snapshot = load_sample_if_present(&sample_file).expect("allocation sample");
    assert_eq!(snapshot.heap_alloc_count_total, FLUSH_EVERY_ALLOC_EVENTS);
    assert_eq!(snapshot.heap_alloc_bytes_total, FLUSH_EVERY_ALLOC_EVENTS);
    let hotspots =
        load_hotspots_if_present(&state.config.hotspot_file).expect("allocation hotspots");
    assert!(hotspots.len() <= MAX_HOTSPOTS);
    assert_eq!(hotspots.len(), 1);
    assert_eq!(hotspots[0].kind, "alloc");
    assert_eq!(hotspots[0].operation, None);
    assert_eq!(hotspots[0].count, 1);
    assert_eq!(hotspots[0].total_bytes, 1);
    assert!(hotspots[0].sample_backtrace.len() <= MAX_BACKTRACE_BYTES);
}

#[test]
fn given_reallocation_flush_boundary_when_recording_then_tracks_new_bytes_once() {
    // Given a state configured to sample only at the reallocation flush
    // boundary.
    let sample_file = unique_path("realloc-boundary-sample");
    let hotspot_file = unique_path("realloc-boundary-hotspots");
    let mut state = probe_state(sample_file.clone(), hotspot_file);
    state.config.alloc_sample_rate = FLUSH_EVERY_ALLOC_EVENTS;

    // When exactly one flush interval of reallocations is recorded.
    for _ in 0..FLUSH_EVERY_ALLOC_EVENTS {
        state.record_realloc(0, 1);
    }

    // Then allocation totals include each new allocation and the live peak is
    // bounded.
    let snapshot = load_sample_if_present(&sample_file).expect("reallocation sample");
    assert_eq!(snapshot.heap_alloc_count_total, FLUSH_EVERY_ALLOC_EVENTS);
    assert_eq!(snapshot.heap_alloc_bytes_total, FLUSH_EVERY_ALLOC_EVENTS);
    assert_eq!(snapshot.heap_peak_live_bytes, FLUSH_EVERY_ALLOC_EVENTS);
}

#[test]
fn given_manager_allocation_delta_when_recording_measurement_then_stores_duration_and_delta() {
    // Given an allocation counter snapshot before manager work.
    let state = probe_state(
        unique_path("manager-sample"),
        unique_path("manager-hotspots"),
    );
    state.record_alloc(5);
    let before = state.counter_snapshot();

    // When manager work allocates and records its elapsed measurement.
    state.record_alloc(7);
    state.record_manager_measurement(42, before);
    let snapshot = state.snapshot();

    // Then only manager work's allocation delta is retained with its duration.
    assert_eq!(snapshot.manager_wall_time_ms, 42);
    assert_eq!(snapshot.manager_heap_alloc_count_total, 1);
    assert_eq!(snapshot.manager_heap_alloc_bytes_total, 7);
}

#[test]
fn given_live_bytes_when_deallocation_exceeds_balance_then_peak_remains_bounded() {
    // Given a state with a small live allocation.
    let state = probe_state(unique_path("live-sample"), unique_path("live-hotspots"));
    state.record_alloc(4);

    // When a deallocation exceeds the current live balance.
    state.record_dealloc(8);

    // Then live bytes do not become a negative peak and future accounting
    // remains valid.
    assert_eq!(
        state.live_bytes.load(std::sync::atomic::Ordering::Relaxed),
        -4
    );
    assert_eq!(state.snapshot().heap_peak_live_bytes, 4);
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
fn given_recorded_state_when_resetting_then_counters_hotspots_and_files_are_empty() {
    // Given a state containing allocation, manager, component, and hotspot
    // data.
    let sample_file = unique_path("reset-sample");
    let hotspot_file = unique_path("reset-hotspots");
    let state = probe_state(sample_file.clone(), hotspot_file.clone());
    state.record_alloc(9);
    state.record_storage_call("put", 4);
    state.record_analytics_call("query", 6);
    state
        .manager_wall_time_ms
        .store(12, std::sync::atomic::Ordering::Relaxed);
    state
        .manager_alloc_count
        .store(2, std::sync::atomic::Ordering::Relaxed);
    state
        .manager_alloc_bytes
        .store(7, std::sync::atomic::Ordering::Relaxed);

    // When the state is reset.
    state.reset();
    let snapshot = state.snapshot();

    // Then all counters and retained hotspot metadata are cleared.
    assert!(snapshot.is_empty());
    assert!(state.hotspot_records().is_empty());
    assert_eq!(
        state
            .hotspot_count
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert_eq!(
        load_sample_if_present(&sample_file)
            .expect("reset sample")
            .heap_alloc_count_total,
        0
    );
    assert!(
        load_hotspots_if_present(&hotspot_file)
            .expect("reset hotspots")
            .is_empty()
    );
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
fn given_equal_count_hotspots_when_flushing_then_orders_by_total_bytes_descending() {
    // Given two distinct hotspots with equal occurrence counts.
    let sample_file = unique_path("sorted-hotspot-sample");
    let hotspot_file = unique_path("sorted-hotspot-records");
    let state = probe_state(sample_file, hotspot_file.clone());
    state.record_hotspot("storage", Some("small"), 2);
    state.record_hotspot("storage", Some("large"), 9);

    // When hotspot records are flushed.
    state.flush();
    let records = load_hotspots_if_present(&hotspot_file).expect("sorted hotspots");

    // Then equal-count records are ordered by descending byte total.
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].operation.as_deref(), Some("large"));
    assert_eq!(records[1].operation.as_deref(), Some("small"));
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
    state.flush();
    let records = load_hotspots_if_present(&state.config.hotspot_file).expect("hotspot records");
    assert_eq!(records.len(), MAX_HOTSPOTS);
    assert!(records.iter().all(|record| {
        record.kind == "storage"
            && record.operation.is_some()
            && record.sample_backtrace.len() <= MAX_BACKTRACE_BYTES
    }));
}

#[test]
fn given_full_hotspot_cache_when_recording_known_operation_then_existing_aggregate_still_updates() {
    // Given a full bounded cache containing the operation recorded below.
    let state = probe_state(
        unique_path("full-cache-existing-sample"),
        unique_path("full-cache-existing-hotspots"),
    );
    // When the already-known operation receives another diagnostic event after
    // the cache reaches its capacity.
    for index in 0..=MAX_HOTSPOTS {
        let (operation, bytes) = if index == MAX_HOTSPOTS {
            ("operation-0".to_string(), 7)
        } else {
            (format!("operation-{index}"), 1)
        };
        state.record_hotspot("storage", Some(&operation), bytes);
    }

    // Then the bounded cache keeps its size while preserving the aggregate
    // total.
    let records = state.hotspot_records();
    assert_eq!(records.len(), MAX_HOTSPOTS);
    let operation_zero = records
        .iter()
        .find(|record| record.operation.as_deref() == Some("operation-0"))
        .expect("known operation remains represented");
    assert_eq!(operation_zero.count, 2);
    assert_eq!(operation_zero.total_bytes, 8);
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
fn given_malformed_or_oversized_record_lists_when_loading_then_rejects_without_partial_data() {
    // Given malformed sample JSON and a valid hotspot list over the record
    // limit.
    let sample_file = unique_path("malformed-sample");
    let hotspot_file = unique_path("too-many-hotspots");
    fs::write(&sample_file, b"not-json").expect("write malformed sample");
    let records = (0..=MAX_HOTSPOTS)
        .map(|index| crate::probe::HotspotRecord {
            kind: "storage".to_string(),
            operation: Some(format!("operation-{index}")),
            stack_hash: format!("{index:016x}"),
            count: 1,
            total_bytes: 1,
            sample_backtrace: String::new(),
        })
        .collect::<Vec<_>>();
    fs::write(
        &hotspot_file,
        serde_json::to_vec(&records).expect("serialize records"),
    )
    .expect("write hotspot records");

    // When both files are loaded.
    let sample = load_sample_if_present(&sample_file);
    let hotspots = load_hotspots_if_present(&hotspot_file);

    // Then malformed and over-limit data are rejected as a whole.
    assert!(sample.is_none());
    assert!(hotspots.is_none());
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
fn given_empty_diagnostic_label_when_recording_hotspot_then_uses_unknown_marker() {
    // Given a state receiving a whitespace-only operation label.
    let state = probe_state(
        unique_path("empty-label-sample"),
        unique_path("empty-label-hotspots"),
    );

    // When the diagnostic hotspot is recorded.
    state.record_hotspot("storage", Some("   "), 1);

    // Then the retained operation is bounded and descriptive rather than empty.
    assert_eq!(
        state.hotspot_records()[0].operation.as_deref(),
        Some("unknown")
    );
}

#[test]
fn given_zero_stack_depth_when_recording_hotspot_then_falls_back_to_bounded_backtrace() {
    // Given a state configured not to retain individual backtrace lines.
    let mut state = probe_state(
        unique_path("fallback-sample"),
        unique_path("fallback-hotspots"),
    );
    state.config.stack_depth = 0;

    // When a hotspot is recorded.
    state.record_hotspot("storage", None, 1);

    // Then the fallback rendering remains within the diagnostic resource bound.
    let record = &state.hotspot_records()[0];
    assert_ne!(record.sample_backtrace, "");
    assert!(record.sample_backtrace.len() <= MAX_BACKTRACE_BYTES);
}

#[test]
fn given_concurrent_hotspot_records_when_aggregating_then_counts_and_bytes_are_lossless() {
    // Given several workers sharing one bounded probe state.
    let state = Arc::new(probe_state(
        unique_path("concurrent-sample"),
        unique_path("concurrent-hotspots"),
    ));
    let workers = (0..4)
        .map(|_| {
            let state = Arc::clone(&state);
            thread::spawn(move || {
                for _ in 0..25 {
                    state.record_storage_call("read", 3);
                }
            })
        })
        .collect::<Vec<_>>();

    // When all workers finish recording the same operation.
    for worker in workers {
        worker.join().expect("worker completes");
    }

    // Then atomic component totals and hotspot aggregation agree.
    let snapshot = state.snapshot();
    let hotspots = state.hotspot_records();
    assert_eq!(snapshot.storage_calls_total, 100);
    assert_eq!(snapshot.storage_bytes_total, 300);
    assert_eq!(hotspots.iter().map(|record| record.count).sum::<u64>(), 100);
    assert_eq!(
        hotspots
            .iter()
            .map(|record| record.total_bytes)
            .sum::<u64>(),
        300
    );
}

#[test]
fn given_poisoned_flush_lock_when_flushing_then_returns_without_panicking() {
    // Given a state whose flush lock was poisoned by a failed owner.
    let state = probe_state(
        unique_path("poisoned-sample"),
        unique_path("poisoned-hotspots"),
    );
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _guard = state.flush_lock.lock().expect("lock available");
        panic!("poison flush lock");
    }));
    assert!(result.is_err());

    // When a flush is attempted after the poison.
    state.flush();

    // Then the lock failure is handled as a no-op rather than a process panic.
    assert!(!state.config.sample_file.exists());
    assert!(!state.config.hotspot_file.exists());
}

#[test]
fn given_disabled_probe_when_using_public_helpers_then_operations_are_noops() {
    if std::env::var_os(DISABLED_CHILD_ENV).is_some() {
        // Given a fresh process with enablement explicitly disabled.
        assert!(!crate::probe::is_enabled());

        // When all public recording and lifecycle helpers are called.
        crate::probe::force_flush();
        crate::probe::reset();
        crate::probe::record_storage_call("read", 1);
        crate::probe::record_queue_call("send", 2);
        crate::probe::record_pubsub_call("publish", 3);
        crate::probe::record_bg_job_call("run", 4);
        crate::probe::record_analytics_call("query", 5);
        let mut future = std::pin::pin!(crate::probe::measure_future(std::future::ready(17_u8)));
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        // Then disabled instrumentation returns promptly without observable
        // state.
        assert_eq!(Future::poll(future.as_mut(), &mut context), Poll::Ready(17));
        assert!(!crate::probe::is_enabled());
        assert!(!PathBuf::from(std::env::var(ENV_SAMPLE_FILE).expect("sample path")).exists());
        assert!(!PathBuf::from(std::env::var(ENV_HOTSPOT_FILE).expect("hotspot path")).exists());
        return;
    }

    // Given a child-process boundary independent of this test process's
    // environment and OnceLock.
    let sample_file = unique_path("disabled-child-sample");
    let hotspot_file = unique_path("disabled-child-hotspots");

    // When the public helpers are exercised in a fresh process with explicit
    // disablement.
    let output = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", DISABLED_HELPERS_TEST_FILTER, "--nocapture"])
        .env(ENV_ENABLED, "0")
        .env(DISABLED_CHILD_ENV, "1")
        .env(ENV_SAMPLE_FILE, &sample_file)
        .env(ENV_HOTSPOT_FILE, &hotspot_file)
        .output()
        .expect("run disabled child test");

    // Then the controlled child proves disabled behavior without shared process
    // state.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "disabled child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.lines().any(|line| line == "running 1 test"),
        "disabled child did not run exactly one test:\n{stdout}"
    );
    let expected_test_line = format!("test {DISABLED_HELPERS_TEST_FILTER} ... ok");
    assert!(
        stdout.lines().any(|line| line == expected_test_line),
        "disabled child did not pass the intended test:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed;")),
        "disabled child summary did not prove one passing test:\n{stdout}"
    );
}

#[test]
fn given_nested_probe_guard_when_entering_again_then_inner_callback_is_skipped() {
    // Given an outer callback holding the thread-local probe guard.
    let mut entered = false;

    // When a callback attempts to enter the guard recursively.
    with_probe_guard(|| {
        with_probe_guard(|| entered = true);
    });

    // Then re-entrancy is suppressed while the outer callback completes.
    assert!(!entered);
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
