use std::{future::Future, time::Duration};

use alloc_counter::AllocationReport;

use crate::{
    JwtDecodeErrorKind,
    test_support::{build_remote_verifier, build_verifier, policy, token, valid_claims},
};

#[tokio::test]
async fn allocation_baseline_static_jwks_successful_verification() {
    let verifier = build_verifier();
    let policy = policy();
    let token = token(valid_claims());

    let report = measure_allocations_async("static_jwks_success", async {
        verifier
            .verify::<serde_json::Value>(&token, &policy)
            .await
            .unwrap();
    })
    .await;

    alloc_counter::emit_report(&report);
    assert!(report.allocation_count > 0);
}

#[tokio::test]
async fn allocation_baseline_remote_jwks_cache_hit_verification() {
    let verifier =
        build_remote_verifier(crate::test_support::CountingTransport::from_bodies(vec![
            crate::test_support::jwks(),
        ]));
    let policy = policy();
    let token = token(valid_claims());
    verifier
        .verify::<serde_json::Value>(&token, &policy)
        .await
        .unwrap();

    let report = measure_allocations_async("remote_jwks_cache_hit", async {
        verifier
            .verify::<serde_json::Value>(&token, &policy)
            .await
            .unwrap();
    })
    .await;

    alloc_counter::emit_report(&report);
    assert!(report.allocation_count > 0);
}

#[tokio::test]
async fn allocation_baseline_negative_malformed_token() {
    let verifier = build_verifier();
    let policy = policy();

    let report = measure_allocations_async("malformed_token", async {
        let error = verifier
            .verify::<serde_json::Value>("not-a-jwt", &policy)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), &JwtDecodeErrorKind::MalformedToken);
    })
    .await;

    alloc_counter::emit_report(&report);
}

#[tokio::test]
async fn allocation_baseline_negative_wrong_audience() {
    let verifier = build_verifier();
    let mut claims = valid_claims();
    claims.registered.aud = Some(crate::Audience::Single("wrong".to_owned()));
    let token = token(claims);
    let policy = policy();

    let report = measure_allocations_async("wrong_audience", async {
        let error = verifier
            .verify::<serde_json::Value>(&token, &policy)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), &JwtDecodeErrorKind::AudienceMismatch);
    })
    .await;

    alloc_counter::emit_report(&report);
}

#[tokio::test]
async fn opt_loop_probe_cache_hit_verification_loop_completes() {
    let verifier =
        build_remote_verifier(crate::test_support::CountingTransport::from_bodies(vec![
            crate::test_support::jwks(),
        ]));
    let policy = policy();
    let token = token(valid_claims());
    verifier
        .verify::<serde_json::Value>(&token, &policy)
        .await
        .unwrap();

    opt_loop_probe::measure_future(async {
        for _ in 0..50 {
            verifier
                .verify::<serde_json::Value>(&token, &policy)
                .await
                .unwrap();
        }
    })
    .await;

    tokio::time::sleep(Duration::from_millis(1)).await;
}

#[tokio::test]
#[ignore = "performance report; run with --ignored --nocapture --test-threads=1"]
async fn perf_loop_jwt_decode_candidate_matrix_reports_allocations_and_cpu() {
    let static_verifier = build_verifier();
    let remote_verifier =
        build_remote_verifier(crate::test_support::CountingTransport::from_bodies(vec![
            crate::test_support::jwks(),
        ]));
    let policy = policy();
    let valid_token = token(valid_claims());
    let mut wrong_audience_claims = valid_claims();
    wrong_audience_claims.registered.aud = Some(crate::Audience::Single("wrong".to_owned()));
    let wrong_audience_token = token(wrong_audience_claims);

    remote_verifier
        .verify::<serde_json::Value>(&valid_token, &policy)
        .await
        .unwrap();

    let static_async_json = measure_allocations_async("matrix_static_async_json", async {
        for _ in 0..100 {
            static_verifier
                .verify::<serde_json::Value>(&valid_token, &policy)
                .await
                .unwrap();
        }
    })
    .await;
    let static_sync_json = measure_allocations("matrix_static_sync_json", || {
        for _ in 0..100 {
            static_verifier
                .verify_static::<serde_json::Value>(&valid_token, &policy)
                .unwrap();
        }
    });
    let static_async_typed = measure_allocations_async("matrix_static_async_typed", async {
        for _ in 0..100 {
            static_verifier
                .verify::<crate::test_support::Claims>(&valid_token, &policy)
                .await
                .unwrap();
        }
    })
    .await;
    let remote_async_json =
        measure_allocations_async("matrix_remote_cache_hit_async_json", async {
            for _ in 0..100 {
                remote_verifier
                    .verify::<serde_json::Value>(&valid_token, &policy)
                    .await
                    .unwrap();
            }
        })
        .await;
    let malformed = measure_allocations_async("matrix_malformed_token", async {
        for _ in 0..100 {
            let error = static_verifier
                .verify::<serde_json::Value>("not-a-jwt", &policy)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), &JwtDecodeErrorKind::MalformedToken);
        }
    })
    .await;
    let wrong_audience = measure_allocations_async("matrix_wrong_audience", async {
        for _ in 0..100 {
            let error = static_verifier
                .verify::<serde_json::Value>(&wrong_audience_token, &policy)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), &JwtDecodeErrorKind::AudienceMismatch);
        }
    })
    .await;

    for report in [
        static_async_json,
        static_sync_json,
        static_async_typed,
        remote_async_json,
        malformed,
        wrong_audience,
    ] {
        alloc_counter::emit_report(&report);
    }

    let static_async_json_cpu = best_of_three_async(|| async {
        for _ in 0..1_000 {
            static_verifier
                .verify::<serde_json::Value>(&valid_token, &policy)
                .await
                .unwrap();
        }
    })
    .await;
    let static_sync_json_cpu = best_of_three(|| {
        for _ in 0..1_000 {
            static_verifier
                .verify_static::<serde_json::Value>(&valid_token, &policy)
                .unwrap();
        }
    });
    let static_async_typed_cpu = best_of_three_async(|| async {
        for _ in 0..1_000 {
            static_verifier
                .verify::<crate::test_support::Claims>(&valid_token, &policy)
                .await
                .unwrap();
        }
    })
    .await;
    let remote_async_json_cpu = best_of_three_async(|| async {
        for _ in 0..1_000 {
            remote_verifier
                .verify::<serde_json::Value>(&valid_token, &policy)
                .await
                .unwrap();
        }
    })
    .await;
    let malformed_cpu = best_of_three_async(|| async {
        for _ in 0..1_000 {
            let error = static_verifier
                .verify::<serde_json::Value>("not-a-jwt", &policy)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), &JwtDecodeErrorKind::MalformedToken);
        }
    })
    .await;
    let wrong_audience_cpu = best_of_three_async(|| async {
        for _ in 0..1_000 {
            let error = static_verifier
                .verify::<serde_json::Value>(&wrong_audience_token, &policy)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), &JwtDecodeErrorKind::AudienceMismatch);
        }
    })
    .await;

    println!(
        "jwt_decode_candidate_matrix_cpu_ns static_async_json={} static_sync_json={} \
         static_async_typed={} remote_cache_hit_async_json={} malformed={} wrong_audience={}",
        static_async_json_cpu.as_nanos(),
        static_sync_json_cpu.as_nanos(),
        static_async_typed_cpu.as_nanos(),
        remote_async_json_cpu.as_nanos(),
        malformed_cpu.as_nanos(),
        wrong_audience_cpu.as_nanos()
    );
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

async fn measure_allocations_async(
    label: &'static str,
    run: impl Future<Output = ()>,
) -> AllocationReport<'static> {
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "performance_tests",
        file!(),
        line!(),
        Some(label),
    );
    run.await;
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

async fn best_of_three_async<Fut>(mut run: impl FnMut() -> Fut) -> Duration
where Fut: Future<Output = ()> {
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let started = std::time::Instant::now();
        run().await;
        best = best.min(started.elapsed());
    }
    best
}
