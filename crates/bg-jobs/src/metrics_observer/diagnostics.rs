use std::time::Duration;

use metrics_facade::{CounterMetric, GaugeMetric, HistogramMetric, counter, gauge, histogram};

use crate::{
    ids::{JobKind, QueueName},
    observer::{CapacityResource, StoreOperation},
};

pub(super) fn observe_attempt_started(queue: QueueName, kind: JobKind, due_delay: Duration) {
    gauge!(GaugeMetric::BgJobsRunningCountMetric, "queue" => queue.as_str(), "kind" => kind.as_str()).increment(1.0);
    histogram!(HistogramMetric::BgJobsDueDelayMs, "queue" => queue.as_str(), "kind" => kind.as_str()).record(due_delay.as_secs_f64() * 1000.0);
}

pub(super) fn observe_attempt_finished(queue: QueueName, kind: JobKind, duration: Duration) {
    gauge!(GaugeMetric::BgJobsRunningCountMetric, "queue" => queue.as_str(), "kind" => kind.as_str()).decrement(1.0);
    histogram!(HistogramMetric::BgWorkerRunOnceMsMetric, "queue" => queue.as_str(), "kind" => kind.as_str()).record(duration.as_secs_f64() * 1000.0);
}

pub(super) fn observe_capacity(resource: CapacityResource) {
    counter!(CounterMetric::BgJobsCapacityLimitedTotal, "resource" => resource.label())
        .increment(1);
}

pub(super) fn observe_reserved(operations: u32) {
    counter!(CounterMetric::BgJobsStoreOperationsReservedTotal).increment(u64::from(operations));
}

pub(super) fn observe_store_call(operation: StoreOperation) {
    counter!(CounterMetric::BgJobsStoreOperationsTotal, "operation" => operation.label())
        .increment(1);
}

pub(super) fn observe_continued(queue: QueueName, kind: JobKind) {
    counter!(CounterMetric::BgWorkerItemsProcessedTotalMetric, "queue" => queue.as_str(), "kind" => kind.as_str(), "outcome" => "continued").increment(1);
}
