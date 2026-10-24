use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use buffered_writes::{TestClock, WriteAttempt};

use super::{
    AtomicSink, BufferStats, BufferedMetering, Deadline, MeteringError, RequestCostSnapshot,
    RequestMeasurement, RequestMeteringContext, SinkError, SinkLimits, begin_database_call,
    begin_request_cost_collection, finish_request_cost_collection,
};

fn measurement(scope: &str, id: &str) -> RequestMeasurement {
    RequestMeasurement::try_new(
        RequestMeteringContext::try_new(scope, id, Duration::from_secs(10)).unwrap(),
        RequestCostSnapshot::default(),
    )
    .unwrap()
}

#[test]
fn given_facade_defaults_when_age_reaches_200ms_then_flush_without_caller_batch_policy() {
    with_metrics_runtime(async {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorded = calls.clone();
        let sink = AtomicSink::try_new(
            SinkLimits::default(),
            move |attempt: WriteAttempt<RequestMeasurement>| {
                let recorded = recorded.clone();
                async move {
                    recorded
                        .lock()
                        .unwrap()
                        .push((attempt.scope().clone(), attempt.items().len()));
                    Ok::<(), SinkError>(())
                }
            },
        )
        .unwrap();
        let clock = TestClock::new();
        let facade = BufferedMetering::builder("requests/v1", sink)
            .with_clock(clock.clone())
            .build()
            .unwrap();
        let admission = facade
            .record_request(measurement("tenant-a", "request-1"))
            .await
            .unwrap();
        assert!(admission.is_buffered());
        clock.advance(Duration::from_millis(199));
        assert_eq!(facade.after_response().await.unwrap().batches_flushed, 0);
        clock.advance(Duration::from_millis(1));
        assert_eq!(facade.after_response().await.unwrap().batches_flushed, 1);
        assert_eq!(calls.lock().unwrap()[0].1, 1);
    });
}

#[test]
fn given_same_request_when_admitted_twice_then_one_write_and_changed_snapshot_is_rejected() {
    with_metrics_runtime(async {
        let sink = AtomicSink::try_new(
            SinkLimits::default(),
            |_: WriteAttempt<RequestMeasurement>| async { Ok::<(), SinkError>(()) },
        )
        .unwrap();
        let facade = BufferedMetering::builder("identity/v1", sink)
            .build()
            .unwrap();
        let first = measurement("tenant-a", "request-1");
        facade.record_request(first.clone()).await.unwrap();
        facade.record_request(first).await.unwrap();
        let changed = RequestMeasurement::try_new(
            RequestMeteringContext::try_new("tenant-a", "request-1", Duration::from_secs(10))
                .unwrap(),
            RequestCostSnapshot {
                db_write_ops: 7,
                ..RequestCostSnapshot::default()
            },
        )
        .unwrap();
        assert!(matches!(
            facade.record_request(changed).await,
            Err(MeteringError::IdentityConflict { .. })
        ));
        assert_eq!(facade.flush_writes().await.unwrap().items_settled, 1);
    });
}

#[test]
fn given_two_tenants_when_flushed_then_never_mix_transaction_scopes() {
    with_metrics_runtime(async {
        let scopes = Arc::new(Mutex::new(Vec::new()));
        let observed = scopes.clone();
        let sink = AtomicSink::try_new(
            SinkLimits::default(),
            move |attempt: WriteAttempt<RequestMeasurement>| {
                let observed = observed.clone();
                async move {
                    assert!(
                        attempt
                            .items()
                            .iter()
                            .all(|item| item.scope() == attempt.scope())
                    );
                    observed.lock().unwrap().push(attempt.scope().clone());
                    Ok::<(), SinkError>(())
                }
            },
        )
        .unwrap();
        let facade = BufferedMetering::builder("scopes/v1", sink)
            .build()
            .unwrap();
        facade
            .record_request(measurement("tenant-a", "request-1"))
            .await
            .unwrap();
        facade
            .record_request(measurement("tenant-b", "request-1"))
            .await
            .unwrap();
        assert_eq!(facade.flush_writes().await.unwrap().batches_flushed, 2);
        assert_eq!(scopes.lock().unwrap().len(), 2);
    });
}

#[test]
fn given_active_request_collection_when_delivery_runs_then_exclude_delivery_database_cost() {
    with_metrics_runtime(async {
        let sink = AtomicSink::try_new(
            SinkLimits::default(),
            |_: WriteAttempt<RequestMeasurement>| async {
                let _guard = begin_database_call("metering-delivery");
                Ok::<(), SinkError>(())
            },
        )
        .unwrap();
        let facade = BufferedMetering::builder("cost-isolation/v1", sink)
            .build()
            .unwrap();
        begin_request_cost_collection(None, || async {
            {
                let _guard = begin_database_call("application");
            }
            facade
                .record_request(measurement("tenant-a", "request-1"))
                .await
                .unwrap();
            assert_eq!(facade.flush_writes().await.unwrap().batches_flushed, 1);
            let snapshot = finish_request_cost_collection(None, 1.0, None).await;
            assert_eq!(snapshot.db_calls, 1);
            assert_eq!(snapshot.db_call_breakdown[0].operation, "application");
        })
        .await;
    });
}

#[test]
fn given_false_flush_policy_when_shutdown_occurs_then_force_young_measurement_delivery() {
    with_metrics_runtime(async {
        let sink = AtomicSink::try_new(
            SinkLimits::default(),
            |_: WriteAttempt<RequestMeasurement>| async { Ok::<(), SinkError>(()) },
        )
        .unwrap();
        let facade = BufferedMetering::builder("shutdown/v1", sink)
            .flush_policy(|_: &BufferStats| false)
            .build()
            .unwrap();
        facade
            .record_request(measurement("tenant-a", "request-1"))
            .await
            .unwrap();
        let report = facade
            .shutdown(Deadline::after(Duration::from_secs(1)))
            .await
            .unwrap();
        assert!(report.is_clean());
        assert_eq!(report.items_settled, 1);
        assert!(matches!(
            facade
                .record_request(measurement("tenant-a", "request-2"))
                .await,
            Err(MeteringError::Closed)
        ));
    });
}

#[test]
fn given_invalid_measurement_when_constructed_then_reject_nonfinite_cost_without_exposing_payload()
{
    let invalid = RequestCostSnapshot {
        wall_ms: f64::NAN,
        ..RequestCostSnapshot::default()
    };
    let context =
        RequestMeteringContext::try_new("tenant-a", "request-1", Duration::from_secs(1)).unwrap();
    assert!(RequestMeasurement::try_new(context, invalid).is_err());
    let record = measurement("private-tenant", "private-request");
    let debug = format!("{record:?}");
    assert!(!debug.contains("private"));
}

fn with_metrics_runtime(future: impl std::future::Future<Output = ()>) {
    let _lock = crate::recorder_tests::METRICS_FACADE_TEST_LOCK
        .lock()
        .expect("metrics test lock");
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("metering test runtime")
        .block_on(future);
}
