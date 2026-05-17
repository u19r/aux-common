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
    claims.registered.aud = crate::Audience::Single("wrong".to_owned());
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
