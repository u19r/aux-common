use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use metrics::{
    Counter, Gauge, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder, SharedString, Unit,
};

use super::{RequestOperation, request_storage_operation_histogram};

fn record_storage_operation_duration(operation: &'static str, duration: Duration) {
    request_storage_operation_histogram(operation).record(duration.as_secs_f64());
}

#[derive(Default)]
struct Observations(Mutex<Vec<f64>>);
impl HistogramFn for Observations {
    fn record(&self, value: f64) {
        self.0.lock().unwrap().push(value);
    }
}

#[derive(Default)]
struct Capture(Mutex<HashMap<Key, Arc<Observations>>>);
impl Recorder for Capture {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn register_counter(&self, _: &Key, _: &Metadata<'_>) -> Counter {
        Counter::noop()
    }
    fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
        Gauge::noop()
    }
    fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(
            self.0
                .lock()
                .unwrap()
                .entry(key.clone())
                .or_default()
                .clone(),
        )
    }
}
impl Capture {
    fn values(&self, api: &str, storage: &str) -> Vec<f64> {
        let key = Key::from_parts(
            "http_storage_operation_duration_seconds",
            &[
                ("api_operation", api.to_owned()),
                ("storage_operation", storage.to_owned()),
            ],
        );
        self.0
            .lock()
            .unwrap()
            .get(&key)
            .map(|v| v.0.lock().unwrap().clone())
            .unwrap_or_default()
    }
}

fn run(capture: &Capture, future: impl std::future::Future<Output = ()>) {
    metrics::with_local_recorder(capture, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future);
    });
}

#[test]
fn given_known_durations_when_recorded_then_counts_sums_and_seconds_are_exact() {
    let capture = Capture::default();
    run(
        &capture,
        RequestOperation::from("POST /example").scope(async {
            record_storage_operation_duration("get_item", Duration::from_millis(25));
            record_storage_operation_duration("get_item", Duration::from_millis(5));
            record_storage_operation_duration("transact_write_items", Duration::from_millis(40));
        }),
    );
    assert_eq!(capture.values("POST /example", "get_item"), [0.025, 0.005]);
    assert_eq!(
        capture.values("POST /example", "transact_write_items"),
        [0.04]
    );
    assert_eq!(capture.0.lock().unwrap().len(), 2);
}

#[test]
fn given_interleaved_requests_when_calls_complete_then_each_operation_keeps_its_scope() {
    let capture = Capture::default();
    run(&capture, async {
        tokio::join!(
            RequestOperation::from("POST /first").scope(async {
                tokio::task::yield_now().await;
                record_storage_operation_duration("get_item", Duration::from_millis(11));
            }),
            RequestOperation::from("GET /second").scope(async {
                record_storage_operation_duration("get_item", Duration::from_millis(22));
                tokio::task::yield_now().await;
                record_storage_operation_duration("get_item", Duration::from_millis(33));
            }),
        );
        record_storage_operation_duration("unscoped", Duration::from_millis(99));
    });
    assert_eq!(capture.values("POST /first", "get_item"), [0.011]);
    assert_eq!(capture.values("GET /second", "get_item"), [0.022, 0.033]);
    assert_eq!(capture.0.lock().unwrap().len(), 2);
}

#[test]
fn given_cost_inherited_worker_when_spawned_then_request_operation_is_not_inherited() {
    let capture = Capture::default();
    run(
        &capture,
        super::begin_request_cost_collection(None, || {
            RequestOperation::from("POST /foreground").scope(async {
                tokio::spawn(super::inherit_request_cost(async {
                    record_storage_operation_duration("worker", Duration::from_millis(99));
                }))
                .await
                .unwrap();
                record_storage_operation_duration("get_item", Duration::from_millis(7));
            })
        }),
    );
    assert_eq!(capture.values("POST /foreground", "get_item"), [0.007]);
    assert_eq!(capture.0.lock().unwrap().len(), 1);
}

#[test]
fn given_cancelled_request_when_next_request_runs_then_context_does_not_leak() {
    let capture = Capture::default();
    run(&capture, async {
        let result = tokio::time::timeout(
            Duration::from_millis(1),
            RequestOperation::from("POST /cancelled").scope(std::future::pending::<()>()),
        )
        .await;
        assert!(result.is_err());
        record_storage_operation_duration("outside", Duration::from_millis(99));
        RequestOperation::from("GET /next")
            .scope(async {
                record_storage_operation_duration("get_item", Duration::from_millis(3));
            })
            .await;
    });
    assert_eq!(capture.values("GET /next", "get_item"), [0.003]);
    assert_eq!(capture.0.lock().unwrap().len(), 1);
}

#[test]
fn given_oversized_operation_when_scoped_then_label_uses_fixed_fallback() {
    let capture = Capture::default();
    let operation = "x".repeat(257);
    run(
        &capture,
        RequestOperation::from(operation.as_str()).scope(async {
            record_storage_operation_duration("get_item", Duration::from_millis(2));
        }),
    );
    assert_eq!(capture.values("_unmatched", "get_item"), [0.002]);
}

#[test]
fn given_foreground_call_handle_when_native_work_is_handed_off_then_only_that_call_is_attributed() {
    let capture = Arc::new(Capture::default());
    // Use one global recorder because the handoff deliberately changes Tokio
    // tasks.
    metrics::set_global_recorder(capture.clone()).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(RequestOperation::from("POST /native").scope(async {
            let native = request_storage_operation_histogram("get_item");
            tokio::spawn(async move {
                native.record(0.004);
                record_storage_operation_duration("unrelated_worker", Duration::from_millis(99));
            })
            .await
            .unwrap();
        }));
    assert_eq!(capture.values("POST /native", "get_item"), [0.004]);
    assert_eq!(capture.0.lock().unwrap().len(), 1);
}
