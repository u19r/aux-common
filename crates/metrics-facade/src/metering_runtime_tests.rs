use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use super::{
    AtomicSink, BufferStats, BufferedMetering, Deadline, LambdaExtensionClient, LambdaIpcConfig,
    LifecycleError, MeteringAttempt, MeteringError, MeteringSetupError, OperationId,
    RequestCostSnapshot, RequestMeasurement, RequestMeteringContext, SinkError, SinkLimits,
    TokioLifecycle,
};

fn measurement(execution: &str) -> RequestMeasurement {
    RequestMeasurement::try_new(
        RequestMeteringContext::try_new("tenant-a", execution, Duration::from_secs(3)).unwrap(),
        RequestCostSnapshot::default(),
    )
    .unwrap()
}

fn ipc_config() -> LambdaIpcConfig {
    LambdaIpcConfig::try_new("127.0.0.1:0".parse().unwrap(), "runtime-test-token").unwrap()
}

#[test]
fn given_default_extension_observer_when_ipc_fails_then_one_writer_projection_records_bounded_lifecycle_failure()
 {
    use tokio::io::AsyncWriteExt;

    use super::{
        CounterMetric, GaugeMetric, MetricLabel,
        metering_metrics::test_support::{CapturingMetrics, FacadeRestore},
    };

    let _lock = super::recorder_tests::METRICS_FACADE_TEST_LOCK
        .lock()
        .unwrap();
    let metrics = Arc::new(CapturingMetrics::default());
    let _restore = FacadeRestore::install(metrics.clone());
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let sink = AtomicSink::try_new(SinkLimits::default(), |_: MeteringAttempt| async {
                Ok::<(), SinkError>(())
            })
            .unwrap();
            let server = BufferedMetering::builder("private-namespace-secret", sink)
                .build_extension(ipc_config())
                .await
                .unwrap();
            assert_eq!(
                metrics.total(
                    GaugeMetric::BufferedMeteringWriters.name(),
                    &[MetricLabel::new("mode", "buffered")]
                ),
                1.0
            );
            let serving = tokio::spawn({
                let server = server.clone();
                async move { server.serve().await }
            });
            let mut stream = tokio::net::TcpStream::connect(server.local_addr().unwrap())
                .await
                .unwrap();
            stream.write_u32(0).await.unwrap();
            tokio::time::timeout(Duration::from_secs(1), async {
                while metrics.total(
                    CounterMetric::BufferedMeteringEventsTotal.name(),
                    &[
                        MetricLabel::new("event", "lifecycle_failed"),
                        MetricLabel::new("detail", "none"),
                    ],
                ) == 0.0
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the server must use the writer's configured observer");
            assert!(
                server
                    .shutdown(Duration::from_secs(1))
                    .await
                    .unwrap()
                    .is_clean()
            );
            serving.await.unwrap().unwrap();
            drop(server);
            assert_eq!(
                metrics.total(
                    GaugeMetric::BufferedMeteringWriters.name(),
                    &[MetricLabel::new("mode", "stopped")]
                ),
                0.0
            );
            assert!(!format!("{:?}", metrics.snapshot()).contains("secret"));
        });
}

#[tokio::test]
async fn given_stopped_extension_when_function_submits_then_transport_failure_preserves_identity_without_claiming_acceptance()
 {
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: MeteringAttempt| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let server = BufferedMetering::builder("runtime/v1", sink)
        .build_extension(ipc_config())
        .await
        .unwrap();
    server
        .begin_invocation("event-1", "provider-id", Duration::from_secs(3))
        .unwrap();
    let serving = tokio::spawn({
        let server = server.clone();
        async move { server.serve().await }
    });
    let mut runtime = LambdaExtensionClient::<RequestMeasurement>::new(
        LambdaIpcConfig::try_new(server.local_addr().unwrap(), "runtime-test-token").unwrap(),
    );
    let metering = BufferedMetering::from(
        runtime
            .begin_invocation("provider-id", "attempt-1")
            .await
            .unwrap(),
    );
    server.shutdown(Duration::from_secs(1)).await.unwrap();
    serving.await.unwrap().unwrap();
    drop(server);
    assert_eq!(
        metering.record_request(measurement("execution-1")).await,
        Err(MeteringError::Unavailable {
            operation_id: Some(OperationId::derive("runtime/v1", "tenant-a", "execution-1")),
            accepted: false,
        })
    );
    assert!(matches!(
        metering.after_response().await,
        Err(LifecycleError::IpcUnavailable { .. })
    ));
}

#[tokio::test]
async fn given_extension_metering_when_invocations_complete_then_identity_fencing_and_extension_shutdown_are_preserved()
 {
    let saved = Arc::new(Mutex::new(Vec::new()));
    let observed = saved.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: MeteringAttempt| {
        let observed = observed.clone();
        async move {
            observed
                .lock()
                .unwrap()
                .extend(attempt.items().iter().map(|item| {
                    (
                        item.scope().as_str().to_owned(),
                        item.request_id().as_str().to_owned(),
                    )
                }));
            Ok::<(), SinkError>(())
        }
    })
    .unwrap();
    let server = BufferedMetering::builder("runtime/v1", sink)
        .flush_policy(|_: &BufferStats| false)
        .build_extension(ipc_config())
        .await
        .unwrap();
    server
        .begin_invocation("event-1", "provider-id", Duration::from_secs(3))
        .unwrap();
    let serving = tokio::spawn({
        let server = server.clone();
        async move { server.serve().await }
    });
    let mut runtime = LambdaExtensionClient::<RequestMeasurement>::new(
        LambdaIpcConfig::try_new(server.local_addr().unwrap(), "runtime-test-token").unwrap(),
    );
    let invocation = runtime
        .begin_invocation("provider-id", "attempt-1")
        .await
        .unwrap();
    assert_eq!(invocation.namespace().as_str(), "runtime/v1");
    let metering = BufferedMetering::from(invocation);
    let input = measurement("execution-1");
    let first = metering.record_request(input.clone()).await.unwrap();
    let retry = metering.clone().record_request(input).await.unwrap();
    assert_eq!(first.operation_id(), retry.operation_id());
    assert_eq!(
        first.operation_id(),
        &OperationId::derive("runtime/v1", "tenant-a", "execution-1")
    );
    assert!(matches!(
        metering.flush_writes().await,
        Err(LifecycleError::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        metering
            .shutdown(Deadline::after(Duration::from_secs(1)))
            .await,
        Err(LifecycleError::InvalidConfiguration { .. })
    ));
    assert!(matches!(
        metering.start(TokioLifecycle::new()).await,
        Err(LifecycleError::InvalidConfiguration { .. })
    ));
    let completed = metering.after_response().await.unwrap();
    assert_eq!(completed.items_settled, 0);
    assert!(!completed.has_failures);
    assert_eq!(metering.after_response().await.unwrap(), completed);
    assert!(
        saved.lock().unwrap().is_empty(),
        "a young buffer remains extension-owned"
    );
    server
        .begin_invocation("event-2", "provider-id", Duration::from_secs(3))
        .unwrap();
    let current = BufferedMetering::from(
        runtime
            .begin_invocation("provider-id", "attempt-2")
            .await
            .unwrap(),
    );
    assert!(matches!(
        metering.record_request(measurement("stale")).await,
        Err(MeteringError::Rejected { .. })
    ));
    assert!(metering.after_response().await.is_err());
    current
        .record_request(measurement("execution-2"))
        .await
        .unwrap();
    current.after_response().await.unwrap();
    let drain = server.shutdown(Duration::from_secs(1)).await.unwrap();
    assert!(drain.is_clean());
    assert_eq!(drain.items_settled, 2);
    serving.await.unwrap().unwrap();
    let mut saved = saved.lock().unwrap().clone();
    saved.sort();
    assert_eq!(
        saved,
        vec![
            ("tenant-a".to_owned(), "execution-1".to_owned()),
            ("tenant-a".to_owned(), "execution-2".to_owned())
        ]
    );
}

#[tokio::test]
async fn given_invalid_extension_setup_when_built_then_configuration_and_lifecycle_failures_remain_distinct()
 {
    let sink = || {
        AtomicSink::try_new(SinkLimits::default(), |_: MeteringAttempt| async {
            Ok::<(), SinkError>(())
        })
        .unwrap()
    };
    assert!(matches!(
        BufferedMetering::builder("", sink())
            .build_extension(ipc_config())
            .await,
        Err(MeteringSetupError::Configuration(_))
    ));
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config =
        LambdaIpcConfig::try_new(occupied.local_addr().unwrap(), "runtime-test-token").unwrap();
    assert!(matches!(
        BufferedMetering::builder("runtime/v1", sink())
            .build_extension(config)
            .await,
        Err(MeteringSetupError::Lifecycle(
            LifecycleError::IpcUnavailable { .. }
        ))
    ));
}
