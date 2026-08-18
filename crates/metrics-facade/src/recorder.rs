use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::{
        Arc, Mutex, OnceLock, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use metrics::{Key, Label, Level, Metadata, with_recorder};

use crate::metrics::{CounterMetric, GaugeMetric, HistogramMetric};
#[cfg(feature = "request-cost")]
use crate::request_cost;

pub(crate) const MAX_METRIC_LABELS: usize = 16;
pub(crate) const MAX_METRIC_LABEL_VALUE_BYTES: usize = 256;
const MAX_HANDLE_CACHE_ENTRIES: usize = 256;
const MAX_REGISTERED_METRIC_KEYS: usize = 4_096;
const INVALID_METRIC_LABEL_VALUE: &str = "<invalid>";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MetricLabel {
    key: &'static str,
    value: String,
    valid: bool,
}

impl MetricLabel {
    #[must_use]
    pub fn new(key: &'static str, value: impl Into<String>) -> Self {
        let value = value.into();
        let valid = value.len() <= MAX_METRIC_LABEL_VALUE_BYTES;
        Self {
            key,
            value: if valid {
                value
            } else {
                INVALID_METRIC_LABEL_VALUE.to_owned()
            },
            valid,
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

    pub(crate) fn is_valid(&self) -> bool {
        self.valid
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

pub(crate) fn labels_are_valid(labels: &[MetricLabel]) -> bool {
    labels.len() <= MAX_METRIC_LABELS && labels.iter().all(MetricLabel::is_valid)
}

pub(crate) fn bounded_labels(labels: Vec<MetricLabel>) -> Vec<MetricLabel> {
    labels.into_iter().take(MAX_METRIC_LABELS).collect()
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
    static COUNTER_HANDLES: RefCell<BoundedHandleCache<CounterCacheKey, metrics::Counter>> =
        RefCell::new(BoundedHandleCache::default());
    static GAUGE_HANDLES: RefCell<BoundedHandleCache<GaugeCacheKey, metrics::Gauge>> =
        RefCell::new(BoundedHandleCache::default());
    static HISTOGRAM_HANDLES: RefCell<BoundedHandleCache<HistogramCacheKey, metrics::Histogram>> =
        RefCell::new(BoundedHandleCache::default());
}

static COUNTER_HANDLE_CACHE_INSERTS: AtomicUsize = AtomicUsize::new(0);
static GAUGE_HANDLE_CACHE_INSERTS: AtomicUsize = AtomicUsize::new(0);
static HISTOGRAM_HANDLE_CACHE_INSERTS: AtomicUsize = AtomicUsize::new(0);

struct BoundedHandleCache<K, H> {
    entries: HashMap<K, H>,
}

impl<K, H> Default for BoundedHandleCache<K, H> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl<K, H> BoundedHandleCache<K, H>
where
    K: Clone + Eq + Hash,
    H: Clone,
{
    fn get(&self, key: &K) -> Option<H> {
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: K, handle: H) {
        if self.entries.len() >= MAX_HANDLE_CACHE_ENTRIES
            && !self.entries.contains_key(&key)
            && let Some(evicted_key) = self.entries.keys().next().cloned()
        {
            self.entries.remove(&evicted_key);
        }
        self.entries.insert(key, handle);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

fn allow_metric_key(key: &Key) -> bool {
    static REGISTERED_KEYS: OnceLock<Mutex<HashSet<Key>>> = OnceLock::new();
    let keys = REGISTERED_KEYS.get_or_init(|| Mutex::new(HashSet::new()));
    let Ok(mut keys) = keys.lock() else {
        return false;
    };
    if keys.contains(key) {
        return true;
    }
    if keys.len() >= MAX_REGISTERED_METRIC_KEYS {
        return false;
    }
    keys.insert(key.clone())
}

impl MetricsCrateFacade {
    fn counter_handle(metric: CounterMetric, labels: &[MetricLabel]) -> metrics::Counter {
        let key = CounterCacheKey {
            metric,
            labels: labels.to_vec(),
        };
        if let Some(handle) = COUNTER_HANDLES.with(|handles| handles.borrow().get(&key)) {
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
        if let Some(handle) = GAUGE_HANDLES.with(|handles| handles.borrow().get(&key)) {
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
        if let Some(handle) = HISTOGRAM_HANDLES.with(|handles| handles.borrow().get(&key)) {
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
    if !labels_are_valid(labels) {
        return metrics::Counter::noop();
    }
    let key = labels_to_key(metric.name(), labels);
    if !allow_metric_key(&key) {
        return metrics::Counter::noop();
    }
    with_recorder(|recorder| recorder.register_counter(&key, metadata()))
}

fn register_gauge_handle(metric: GaugeMetric, labels: &[MetricLabel]) -> metrics::Gauge {
    if !labels_are_valid(labels) {
        return metrics::Gauge::noop();
    }
    let key = labels_to_key(metric.name(), labels);
    if !allow_metric_key(&key) {
        return metrics::Gauge::noop();
    }
    with_recorder(|recorder| recorder.register_gauge(&key, metadata()))
}

fn register_histogram_handle(
    metric: HistogramMetric,
    labels: &[MetricLabel],
) -> metrics::Histogram {
    if !labels_are_valid(labels) {
        return metrics::Histogram::noop();
    }
    let key = labels_to_key(metric.name(), labels);
    if !allow_metric_key(&key) {
        return metrics::Histogram::noop();
    }
    with_recorder(|recorder| recorder.register_histogram(&key, metadata()))
}

impl MetricsFacade for MetricsCrateFacade {
    fn increment_counter(&self, metric: CounterMetric, labels: &[MetricLabel], value: u64) {
        if !labels_are_valid(labels) {
            return;
        }
        Self::counter_handle(metric, labels).increment(value);
        #[cfg(feature = "request-cost")]
        request_cost::record_counter(metric, labels, value);
    }

    fn absolute_counter(&self, metric: CounterMetric, labels: &[MetricLabel], value: u64) {
        if !labels_are_valid(labels) {
            return;
        }
        Self::counter_handle(metric, labels).absolute(value);
    }

    fn increment_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        if !labels_are_valid(labels) {
            return;
        }
        Self::gauge_handle(metric, labels).increment(value);
    }

    fn decrement_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        if !labels_are_valid(labels) {
            return;
        }
        Self::gauge_handle(metric, labels).decrement(value);
    }

    fn set_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        if !labels_are_valid(labels) {
            return;
        }
        Self::gauge_handle(metric, labels).set(value);
        #[cfg(feature = "request-cost")]
        request_cost::record_gauge(metric, labels, request_cost::GaugeUpdate::Set);
    }

    fn record_histogram(&self, metric: HistogramMetric, labels: &[MetricLabel], value: f64) {
        if !labels_are_valid(labels) {
            return;
        }
        Self::histogram_handle(metric, labels).record(value);
        #[cfg(feature = "request-cost")]
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

#[cfg(test)]
pub(crate) fn metrics_crate_facade_thread_local_cache_sizes() -> (usize, usize, usize) {
    (
        COUNTER_HANDLES.with(|handles| handles.borrow().len()),
        GAUGE_HANDLES.with(|handles| handles.borrow().len()),
        HISTOGRAM_HANDLES.with(|handles| handles.borrow().len()),
    )
}

#[derive(Clone)]
pub struct CounterHandle {
    metric: CounterMetric,
    labels: Vec<MetricLabel>,
    facade: Arc<dyn MetricsFacade>,
    enabled: bool,
}

impl CounterHandle {
    pub(crate) fn new(metric: CounterMetric, labels: Vec<MetricLabel>) -> Self {
        let enabled = crate::recorder::labels_are_valid(&labels);
        Self {
            metric,
            labels: crate::recorder::bounded_labels(labels),
            facade: active_metrics_facade(),
            enabled,
        }
    }

    pub fn increment(&self, value: u64) {
        if !self.enabled {
            return;
        }
        self.facade
            .increment_counter(self.metric, &self.labels, value);
    }

    pub fn absolute(&self, value: u64) {
        if !self.enabled {
            return;
        }
        self.facade
            .absolute_counter(self.metric, &self.labels, value);
    }
}

#[derive(Clone)]
pub struct GaugeHandle {
    metric: GaugeMetric,
    labels: Vec<MetricLabel>,
    facade: Arc<dyn MetricsFacade>,
    enabled: bool,
}

impl GaugeHandle {
    pub(crate) fn new(metric: GaugeMetric, labels: Vec<MetricLabel>) -> Self {
        let enabled = crate::recorder::labels_are_valid(&labels);
        Self {
            metric,
            labels: crate::recorder::bounded_labels(labels),
            facade: active_metrics_facade(),
            enabled,
        }
    }

    pub fn increment(&self, value: f64) {
        if !self.enabled {
            return;
        }
        self.facade
            .increment_gauge(self.metric, &self.labels, value);
    }

    pub fn decrement(&self, value: f64) {
        if !self.enabled {
            return;
        }
        self.facade
            .decrement_gauge(self.metric, &self.labels, value);
    }

    pub fn set(&self, value: f64) {
        if !self.enabled {
            return;
        }
        self.facade.set_gauge(self.metric, &self.labels, value);
    }
}

#[derive(Clone)]
pub struct HistogramHandle {
    metric: HistogramMetric,
    labels: Vec<MetricLabel>,
    facade: Arc<dyn MetricsFacade>,
    enabled: bool,
}

impl HistogramHandle {
    pub(crate) fn new(metric: HistogramMetric, labels: Vec<MetricLabel>) -> Self {
        let enabled = crate::recorder::labels_are_valid(&labels);
        Self {
            metric,
            labels: crate::recorder::bounded_labels(labels),
            facade: active_metrics_facade(),
            enabled,
        }
    }

    pub fn record(&self, value: f64) {
        if !self.enabled {
            return;
        }
        self.facade
            .record_histogram(self.metric, &self.labels, value);
    }
}
