use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use metrics_facade::{CounterMetric, GaugeMetric, HistogramMetric, MetricLabel, MetricsFacade};

use crate::{
    JobKind, QueueName,
    metrics_observer::MetricsObserver,
    observer::{JobEvent, JobObserver},
};

#[derive(Debug, Default)]
struct RecordingFacade(Mutex<Vec<(String, Vec<MetricLabel>, f64)>>);

impl RecordingFacade {
    fn record_sample(&self, name: &str, labels: &[MetricLabel], value: f64) {
        self.0
            .lock()
            .expect("samples")
            .push((name.to_owned(), labels.to_vec(), value));
    }
}

impl MetricsFacade for RecordingFacade {
    fn increment_counter(&self, metric: CounterMetric, labels: &[MetricLabel], value: u64) {
        self.record_sample(metric.name(), labels, value as f64);
    }
    fn absolute_counter(&self, metric: CounterMetric, labels: &[MetricLabel], value: u64) {
        self.record_sample(metric.name(), labels, value as f64);
    }
    fn increment_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        self.record_sample(metric.name(), labels, value);
    }
    fn decrement_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        self.record_sample(metric.name(), labels, -value);
    }
    fn set_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        self.record_sample(metric.name(), labels, value);
    }
    fn record_histogram(&self, metric: HistogramMetric, labels: &[MetricLabel], value: f64) {
        self.record_sample(metric.name(), labels, value);
    }
}

struct RestoreFacade(Arc<dyn MetricsFacade>);

impl Drop for RestoreFacade {
    fn drop(&mut self) {
        metrics_facade::set_metrics_facade(self.0.clone());
    }
}

#[test]
fn given_attempt_events_when_exported_then_kind_labels_durations_and_active_balance_are_preserved()
{
    let facade = Arc::new(RecordingFacade::default());
    let _restore = RestoreFacade(metrics_facade::set_metrics_facade(facade.clone()));
    let observer = MetricsObserver::new();
    let queue = QueueName::try_new("diagnostic-export-test").expect("queue");
    let kind = JobKind::try_new("diagnostic-export-handler").expect("kind");
    observer.observe(JobEvent::AttemptStarted {
        queue: queue.clone(),
        kind: kind.clone(),
        due_delay: Duration::from_millis(42),
    });
    observer.observe(JobEvent::Continued {
        queue: queue.clone(),
        kind: kind.clone(),
    });
    observer.observe(JobEvent::AttemptFinished {
        queue,
        kind,
        duration: Duration::from_millis(5),
    });
    let samples = facade.0.lock().expect("samples");
    let values = |name: &str| {
        samples
            .iter()
            .filter(|(metric, labels, _)| {
                metric == name
                    && labels.iter().any(|label| {
                        label.key() == "kind" && label.value() == "diagnostic-export-handler"
                    })
            })
            .map(|(_, _, value)| *value)
            .collect::<Vec<_>>()
    };
    assert_eq!(values("bg.jobs.due.delay.ms"), vec![42.0]);
    assert_eq!(values("bg.worker.run.once.ms"), vec![5.0]);
    assert_eq!(values("bg.jobs.running.count"), vec![1.0, -1.0]);
    assert_eq!(values("bg.worker.items.processed.total"), vec![1.0]);
    assert!(
        samples
            .iter()
            .filter(|(_, labels, _)| labels.iter().any(|label| label.key() == "kind"))
            .all(|(_, labels, _)| !labels
                .iter()
                .any(|label| ["tenant", "job_id", "execution_id"].contains(&label.key())))
    );
}
