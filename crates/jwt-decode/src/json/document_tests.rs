use std::{hint::black_box, time::Duration};

use alloc_counter::AllocationReport;
use proptest::prelude::*;

use crate::json::JsonDocument;

const HIGH_CARDINALITY_MEMBER_COUNT: usize = 512;

#[test]
fn given_trailing_json_value_when_validating_document_then_rejects_input() {
    assert!(JsonDocument::reject_duplicate_members(br#"{} {}"#).is_err());
}

#[test]
fn given_trailing_json_value_when_parsing_document_then_rejects_input() {
    assert!(JsonDocument::value_rejecting_duplicate_members(br#"{} []"#).is_err());
}

#[test]
fn given_trailing_whitespace_when_parsing_document_then_accepts_input() {
    assert!(JsonDocument::reject_duplicate_members(b"{} \n\t").is_ok());
    assert!(JsonDocument::value_rejecting_duplicate_members(b"{} \n\t").is_ok());
}

#[test]
fn given_high_cardinality_unique_object_when_validating_then_accepts_all_members() {
    let document = json_object_with_members(HIGH_CARDINALITY_MEMBER_COUNT);

    assert!(JsonDocument::reject_duplicate_members(&document).is_ok());
    let value = JsonDocument::value_rejecting_duplicate_members(&document)
        .expect("unique object should parse");
    assert_eq!(
        value.as_object().map_or(0, serde_json::Map::len),
        HIGH_CARDINALITY_MEMBER_COUNT
    );
}

#[test]
fn given_high_cardinality_object_with_overflow_duplicate_when_validating_then_rejects_input() {
    let document = json_object_with_duplicate(HIGH_CARDINALITY_MEMBER_COUNT, 17);

    assert!(JsonDocument::reject_duplicate_members(&document).is_err());
    assert!(JsonDocument::value_rejecting_duplicate_members(&document).is_err());
}

fn json_object_with_members(member_count: usize) -> Vec<u8> {
    let mut document = String::from("{");
    for index in 0..member_count {
        if index > 0 {
            document.push(',');
        }
        document.push_str(&format!("\"member_{index}\":null"));
    }
    document.push('}');
    document.into_bytes()
}

fn json_object_with_duplicate(member_count: usize, duplicate_index: usize) -> Vec<u8> {
    let mut document = json_object_with_members(member_count);
    assert_eq!(document.pop(), Some(b'}'));
    document.extend_from_slice(format!(",\"member_{duplicate_index}\":null}}").as_bytes());
    document
}

#[test]
#[ignore = "performance report; run with --ignored --nocapture --test-threads=1"]
fn perf_loop_duplicate_member_scan_reports_cardinality_scaling() {
    const SMALL_MEMBER_COUNT: usize = 512;
    const LARGE_MEMBER_COUNT: usize = 2_048;
    let small = json_object_with_members(SMALL_MEMBER_COUNT);
    let large = json_object_with_members(LARGE_MEMBER_COUNT);

    let small_allocations = measure_allocations("json_duplicate_scan_small", || {
        assert!(black_box(JsonDocument::reject_duplicate_members(&small)).is_ok());
    });
    let large_allocations = measure_allocations("json_duplicate_scan_large", || {
        assert!(black_box(JsonDocument::reject_duplicate_members(&large)).is_ok());
    });
    alloc_counter::emit_report(&small_allocations).expect("allocation report");
    alloc_counter::emit_report(&large_allocations).expect("allocation report");

    let small_cpu = best_of_three(|| {
        assert!(black_box(JsonDocument::reject_duplicate_members(&small)).is_ok());
    });
    let large_cpu = best_of_three(|| {
        assert!(black_box(JsonDocument::reject_duplicate_members(&large)).is_ok());
    });
    println!(
        "jwt_json_duplicate_scan_cpu_ns small_members={SMALL_MEMBER_COUNT} \
         large_members={LARGE_MEMBER_COUNT} small={} large={} normalized_large={:.2}",
        small_cpu.as_nanos(),
        large_cpu.as_nanos(),
        normalized_duration(large_cpu, small_cpu, SMALL_MEMBER_COUNT, LARGE_MEMBER_COUNT)
    );
}

fn normalized_duration(
    large: Duration,
    small: Duration,
    small_members: usize,
    large_members: usize,
) -> f64 {
    let small_per_member = small.as_secs_f64() / small_members as f64;
    let large_per_member = large.as_secs_f64() / large_members as f64;
    large_per_member / small_per_member
}

fn measure_allocations(label: &'static str, run: impl FnOnce()) -> AllocationReport<'static> {
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "performance_tests",
        file!(),
        line!(),
        Some(label),
    );
    run();
    guard.finish()
}

fn best_of_three(mut run: impl FnMut()) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let started = std::time::Instant::now();
        run();
        best = best.min(started.elapsed());
    }
    best
}

proptest! {
    #[test]
    fn given_duplicated_member_when_validating_then_rejects(
        key in "[a-z]{1,8}",
        filler in prop::collection::hash_set("[a-z]{1,8}", 0..3),
    ) {
        // Given an object where one member name repeats exactly, surrounded
        // by filler members that never collide with it.
        prop_assume!(!filler.contains(&key));
        let mut document = String::from("{");
        for (index, name) in filler.iter().enumerate() {
            if index > 0 {
                document.push(',');
            }
            document.push_str(&format!("\"{name}\":{index}"));
        }
        if !filler.is_empty() {
            document.push(',');
        }
        document.push_str(&format!("\"{key}\":1,\"{key}\":2}}"));
        let bytes = document.into_bytes();

        // When both duplicate-rejecting entry points inspect the document.
        // Then neither entry point accepts the attacker-controlled duplicate.
        prop_assert!(JsonDocument::reject_duplicate_members(&bytes).is_err());
        prop_assert!(
            JsonDocument::value_rejecting_duplicate_members(&bytes).is_err()
        );
    }
}
