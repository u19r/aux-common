use std::{
    cell::RefCell,
    collections::HashMap,
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use metrics::{Key, Label, Level, Metadata, with_recorder};

use crate::{
    metrics::{CounterMetric, GaugeMetric, HistogramMetric},
    request_cost,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MetricLabel {
    key: &'static str,
    value: String,
}

impl MetricLabel {
    #[must_use]
    pub fn new(key: &'static str, value: impl Into<String>) -> Self {
        Self {
            key,
            value: value.into(),
        }
    }

    #[must_use]
    pub fn key(&self) -> &'static str {
        self.key
    }

    #[must_use]
    pub fn value(&self) -> &str {
        self.value.as_str()
    }

    fn to_metrics_label(&self) -> Label {
        Label::new(self.key, self.value.clone())
    }
}

fn labels_to_key(name: &'static str, labels: &[MetricLabel]) -> Key {
    if labels.is_empty() {
        return Key::from_static_name(name);
    }
    Key::from_parts(
        name,
        labels
            .iter()
            .map(MetricLabel::to_metrics_label)
            .collect::<Vec<_>>(),
    )
}

fn metadata() -> &'static Metadata<'static> {
    static METADATA: Metadata<'static> =
        Metadata::new(module_path!(), Level::INFO, Some(module_path!()));
    &METADATA
}

pub trait MetricsFacade: std::fmt::Debug + Send + Sync + 'static {
    fn increment_counter(&self, metric: CounterMetric, labels: &[MetricLabel], value: u64);
    fn absolute_counter(&self, metric: CounterMetric, labels: &[MetricLabel], value: u64);
    fn increment_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64);
    fn decrement_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64);
    fn set_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64);
    fn record_histogram(&self, metric: HistogramMetric, labels: &[MetricLabel], value: f64);
}

#[derive(Debug, Default)]
pub struct MetricsCrateFacade;

/// Cumulative thread-local handle cache insertions by metric kind.
///
/// Metric handles are cached per thread to avoid contended global bookkeeping
/// in hot record paths. The snapshot counts cache misses that populated those
/// per-thread maps; it is not a live global map length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsCrateFacadeCacheSnapshot {
    pub counters: usize,
    pub gauges: usize,
    pub histograms: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CounterCacheKey {
    metric: CounterMetric,
    labels: Vec<MetricLabel>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct GaugeCacheKey {
    metric: GaugeMetric,
    labels: Vec<MetricLabel>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct HistogramCacheKey {
    metric: HistogramMetric,
    labels: Vec<MetricLabel>,
}

thread_local! {
    static COUNTER_HANDLES: RefCell<HashMap<CounterCacheKey, metrics::Counter>> =
        RefCell::new(HashMap::new());
    static GAUGE_HANDLES: RefCell<HashMap<GaugeCacheKey, metrics::Gauge>> =
        RefCell::new(HashMap::new());
    static HISTOGRAM_HANDLES: RefCell<HashMap<HistogramCacheKey, metrics::Histogram>> =
        RefCell::new(HashMap::new());
}

static COUNTER_HANDLE_CACHE_INSERTS: AtomicUsize = AtomicUsize::new(0);
static GAUGE_HANDLE_CACHE_INSERTS: AtomicUsize = AtomicUsize::new(0);
static HISTOGRAM_HANDLE_CACHE_INSERTS: AtomicUsize = AtomicUsize::new(0);

impl MetricsCrateFacade {
    fn counter_handle(metric: CounterMetric, labels: &[MetricLabel]) -> metrics::Counter {
        let key = CounterCacheKey {
            metric,
            labels: labels.to_vec(),
        };
        if let Some(handle) = COUNTER_HANDLES.with(|handles| handles.borrow().get(&key).cloned()) {
            return handle;
        }
        let handle = register_counter_handle(metric, labels);
        COUNTER_HANDLES.with(|handles| {
            handles.borrow_mut().insert(key, handle.clone());
            COUNTER_HANDLE_CACHE_INSERTS.fetch_add(1, Ordering::Relaxed);
        });
        handle
    }

    fn gauge_handle(metric: GaugeMetric, labels: &[MetricLabel]) -> metrics::Gauge {
        let key = GaugeCacheKey {
            metric,
            labels: labels.to_vec(),
        };
        if let Some(handle) = GAUGE_HANDLES.with(|handles| handles.borrow().get(&key).cloned()) {
            return handle;
        }
        let handle = register_gauge_handle(metric, labels);
        GAUGE_HANDLES.with(|handles| {
            handles.borrow_mut().insert(key, handle.clone());
            GAUGE_HANDLE_CACHE_INSERTS.fetch_add(1, Ordering::Relaxed);
        });
        handle
    }

    fn histogram_handle(metric: HistogramMetric, labels: &[MetricLabel]) -> metrics::Histogram {
        let key = HistogramCacheKey {
            metric,
            labels: labels.to_vec(),
        };
        if let Some(handle) = HISTOGRAM_HANDLES.with(|handles| handles.borrow().get(&key).cloned())
        {
            return handle;
        }
        let handle = register_histogram_handle(metric, labels);
        HISTOGRAM_HANDLES.with(|handles| {
            handles.borrow_mut().insert(key, handle.clone());
            HISTOGRAM_HANDLE_CACHE_INSERTS.fetch_add(1, Ordering::Relaxed);
        });
        handle
    }
}

fn register_counter_handle(metric: CounterMetric, labels: &[MetricLabel]) -> metrics::Counter {
    let key = labels_to_key(metric.name(), labels);
    with_recorder(|recorder| recorder.register_counter(&key, metadata()))
}

fn register_gauge_handle(metric: GaugeMetric, labels: &[MetricLabel]) -> metrics::Gauge {
    let key = labels_to_key(metric.name(), labels);
    with_recorder(|recorder| recorder.register_gauge(&key, metadata()))
}

fn register_histogram_handle(
    metric: HistogramMetric,
    labels: &[MetricLabel],
) -> metrics::Histogram {
    let key = labels_to_key(metric.name(), labels);
    with_recorder(|recorder| recorder.register_histogram(&key, metadata()))
}

impl MetricsFacade for MetricsCrateFacade {
    fn increment_counter(&self, metric: CounterMetric, labels: &[MetricLabel], value: u64) {
        Self::counter_handle(metric, labels).increment(value);
        request_cost::record_counter(metric, labels, value);
    }

    fn absolute_counter(&self, metric: CounterMetric, labels: &[MetricLabel], value: u64) {
        Self::counter_handle(metric, labels).absolute(value);
    }

    fn increment_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        Self::gauge_handle(metric, labels).increment(value);
    }

    fn decrement_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        Self::gauge_handle(metric, labels).decrement(value);
    }

    fn set_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        Self::gauge_handle(metric, labels).set(value);
        request_cost::record_gauge(metric, labels, request_cost::GaugeUpdate::Set);
    }

    fn record_histogram(&self, metric: HistogramMetric, labels: &[MetricLabel], value: f64) {
        Self::histogram_handle(metric, labels).record(value);
        request_cost::record_histogram(metric, labels, value);
    }
}

static METRICS_FACADE: OnceLock<RwLock<Arc<dyn MetricsFacade>>> = OnceLock::new();

fn metrics_facade_cell() -> &'static RwLock<Arc<dyn MetricsFacade>> {
    METRICS_FACADE.get_or_init(|| RwLock::new(Arc::new(MetricsCrateFacade)))
}

#[must_use]
pub fn active_metrics_facade() -> Arc<dyn MetricsFacade> {
    match metrics_facade_cell().read() {
        Ok(guard) => Arc::clone(&guard),
        Err(poisoned) => Arc::clone(&poisoned.into_inner()),
    }
}

pub fn set_metrics_facade(facade: Arc<dyn MetricsFacade>) -> Arc<dyn MetricsFacade> {
    match metrics_facade_cell().write() {
        Ok(mut guard) => std::mem::replace(&mut *guard, facade),
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            std::mem::replace(&mut *guard, facade)
        }
    }
}

#[must_use]
pub fn reset_metrics_facade() -> Arc<dyn MetricsFacade> {
    set_metrics_facade(Arc::new(MetricsCrateFacade))
}

#[must_use]
pub fn metrics_crate_facade_cache_snapshot() -> MetricsCrateFacadeCacheSnapshot {
    MetricsCrateFacadeCacheSnapshot {
        counters: COUNTER_HANDLE_CACHE_INSERTS.load(Ordering::Relaxed),
        gauges: GAUGE_HANDLE_CACHE_INSERTS.load(Ordering::Relaxed),
        histograms: HISTOGRAM_HANDLE_CACHE_INSERTS.load(Ordering::Relaxed),
    }
}

#[derive(Clone)]
pub struct CounterHandle {
    metric: CounterMetric,
    labels: Vec<MetricLabel>,
    facade: Arc<dyn MetricsFacade>,
}

impl CounterHandle {
    pub(crate) fn new(metric: CounterMetric, labels: Vec<MetricLabel>) -> Self {
        Self {
            metric,
            labels,
            facade: active_metrics_facade(),
        }
    }

    pub fn increment(&self, value: u64) {
        self.facade
            .increment_counter(self.metric, &self.labels, value);
    }

    pub fn absolute(&self, value: u64) {
        self.facade
            .absolute_counter(self.metric, &self.labels, value);
    }
}

#[derive(Clone)]
pub struct GaugeHandle {
    metric: GaugeMetric,
    labels: Vec<MetricLabel>,
    facade: Arc<dyn MetricsFacade>,
}

impl GaugeHandle {
    pub(crate) fn new(metric: GaugeMetric, labels: Vec<MetricLabel>) -> Self {
        Self {
            metric,
            labels,
            facade: active_metrics_facade(),
        }
    }

    pub fn increment(&self, value: f64) {
        self.facade
            .increment_gauge(self.metric, &self.labels, value);
    }

    pub fn decrement(&self, value: f64) {
        self.facade
            .decrement_gauge(self.metric, &self.labels, value);
    }

    pub fn set(&self, value: f64) {
        self.facade.set_gauge(self.metric, &self.labels, value);
    }
}

#[derive(Clone)]
pub struct HistogramHandle {
    metric: HistogramMetric,
    labels: Vec<MetricLabel>,
    facade: Arc<dyn MetricsFacade>,
}

impl HistogramHandle {
    pub(crate) fn new(metric: HistogramMetric, labels: Vec<MetricLabel>) -> Self {
        Self {
            metric,
            labels,
            facade: active_metrics_facade(),
        }
    }

    pub fn record(&self, value: f64) {
        self.facade
            .record_histogram(self.metric, &self.labels, value);
    }
}
