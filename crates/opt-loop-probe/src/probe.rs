use std::{
    alloc::{GlobalAlloc, Layout},
    backtrace::Backtrace,
    cell::Cell,
    collections::{HashMap, hash_map::DefaultHasher},
    env, fs,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use mimalloc::MiMalloc;
use serde::{Deserialize, Serialize};

use crate::constants::{
    DEFAULT_ALLOC_SAMPLE_RATE, DEFAULT_STACK_DEPTH, ENV_ALLOC_SAMPLE_RATE, ENV_ENABLED,
    ENV_HOTSPOT_FILE, ENV_PHASE, ENV_SAMPLE_FILE, ENV_SAMPLE_INDEX, ENV_STACK_DEPTH, ENV_TARGET_ID,
    FLUSH_EVERY_ALLOC_EVENTS,
};

thread_local! {
    static IN_PROBE: Cell<bool> = const { Cell::new(false) };
}

#[derive(Debug, Clone)]
pub(crate) struct ProbeConfig {
    pub(crate) target_id: String,
    pub(crate) phase: String,
    pub(crate) sample_index: u32,
    pub(crate) sample_file: PathBuf,
    pub(crate) hotspot_file: PathBuf,
    pub(crate) alloc_sample_rate: u64,
    pub(crate) stack_depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeSample {
    pub target_id: String,
    pub phase: String,
    pub sample_index: u32,
    pub timestamp_unix_ms: u64,
    pub process_id: u32,
    #[serde(default)]
    pub wall_time_ms: u64,
    #[serde(default)]
    pub manager_wall_time_ms: u64,
    pub heap_alloc_count_total: u64,
    pub heap_alloc_bytes_total: u64,
    pub heap_peak_live_bytes: u64,
    #[serde(default)]
    pub manager_heap_alloc_count_total: u64,
    #[serde(default)]
    pub manager_heap_alloc_bytes_total: u64,
    pub external_pause_count_total: u64,
    pub storage_calls_total: u64,
    pub storage_bytes_total: u64,
    pub queue_calls_total: u64,
    pub queue_bytes_total: u64,
    pub pubsub_calls_total: u64,
    pub pubsub_bytes_total: u64,
    pub bg_job_calls_total: u64,
    pub bg_job_bytes_total: u64,
    #[serde(default)]
    pub analytics_calls_total: u64,
    #[serde(default)]
    pub analytics_bytes_total: u64,
}

impl Default for ProbeSample {
    fn default() -> Self {
        Self {
            target_id: String::new(),
            phase: String::new(),
            sample_index: 0,
            timestamp_unix_ms: 0,
            process_id: std::process::id(),
            wall_time_ms: 0,
            manager_wall_time_ms: 0,
            heap_alloc_count_total: 0,
            heap_alloc_bytes_total: 0,
            heap_peak_live_bytes: 0,
            manager_heap_alloc_count_total: 0,
            manager_heap_alloc_bytes_total: 0,
            external_pause_count_total: 0,
            storage_calls_total: 0,
            storage_bytes_total: 0,
            queue_calls_total: 0,
            queue_bytes_total: 0,
            pubsub_calls_total: 0,
            pubsub_bytes_total: 0,
            bg_job_calls_total: 0,
            bg_job_bytes_total: 0,
            analytics_calls_total: 0,
            analytics_bytes_total: 0,
        }
    }
}

impl ProbeSample {
    pub(crate) fn is_empty(&self) -> bool {
        self.wall_time_ms == 0
            && self.manager_wall_time_ms == 0
            && self.heap_alloc_count_total == 0
            && self.heap_alloc_bytes_total == 0
            && self.heap_peak_live_bytes == 0
            && self.manager_heap_alloc_count_total == 0
            && self.manager_heap_alloc_bytes_total == 0
            && self.external_pause_count_total == 0
            && self.storage_calls_total == 0
            && self.storage_bytes_total == 0
            && self.queue_calls_total == 0
            && self.queue_bytes_total == 0
            && self.pubsub_calls_total == 0
            && self.pubsub_bytes_total == 0
            && self.bg_job_calls_total == 0
            && self.bg_job_bytes_total == 0
            && self.analytics_calls_total == 0
            && self.analytics_bytes_total == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotRecord {
    pub kind: String,
    pub operation: Option<String>,
    pub stack_hash: String,
    pub count: u64,
    pub total_bytes: u64,
    pub sample_backtrace: String,
}

#[derive(Debug, Clone)]
pub(crate) struct HotspotAggregate {
    kind: String,
    operation: Option<String>,
    stack_hash: String,
    count: u64,
    total_bytes: u64,
    sample_backtrace: String,
}

impl HotspotAggregate {
    fn to_record(&self) -> HotspotRecord {
        HotspotRecord {
            kind: self.kind.clone(),
            operation: self.operation.clone(),
            stack_hash: self.stack_hash.clone(),
            count: self.count,
            total_bytes: self.total_bytes,
            sample_backtrace: self.sample_backtrace.clone(),
        }
    }
}

pub(crate) struct ProbeState {
    pub(crate) config: ProbeConfig,
    pub(crate) alloc_count: AtomicU64,
    pub(crate) alloc_bytes: AtomicU64,
    pub(crate) live_bytes: AtomicI64,
    pub(crate) peak_live_bytes: AtomicU64,
    pub(crate) manager_wall_time_ms: AtomicU64,
    pub(crate) manager_alloc_count: AtomicU64,
    pub(crate) manager_alloc_bytes: AtomicU64,
    pub(crate) storage_calls: AtomicU64,
    pub(crate) storage_bytes: AtomicU64,
    pub(crate) queue_calls: AtomicU64,
    pub(crate) queue_bytes: AtomicU64,
    pub(crate) pubsub_calls: AtomicU64,
    pub(crate) pubsub_bytes: AtomicU64,
    pub(crate) bg_job_calls: AtomicU64,
    pub(crate) bg_job_bytes: AtomicU64,
    pub(crate) analytics_calls: AtomicU64,
    pub(crate) analytics_bytes: AtomicU64,
    pub(crate) hotspots: Mutex<HashMap<String, HotspotAggregate>>,
    pub(crate) flush_lock: Mutex<()>,
}

impl ProbeState {
    fn from_env() -> Option<Self> {
        if !env_truthy(ENV_ENABLED) {
            return None;
        }

        let target_id = env::var(ENV_TARGET_ID).unwrap_or_else(|_| "unknown".to_string());
        let phase = env::var(ENV_PHASE).unwrap_or_else(|_| "unknown".to_string());
        let sample_index = env::var(ENV_SAMPLE_INDEX)
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        let sample_file = env::var(ENV_SAMPLE_FILE).map_or_else(
            |_| {
                PathBuf::from(format!(
                    "tmp/opt-loop/runs/{target_id}/{phase}/sample-{sample_index}.json"
                ))
            },
            PathBuf::from,
        );

        let hotspot_file = env::var(ENV_HOTSPOT_FILE).map_or_else(
            |_| {
                PathBuf::from(format!(
                    "tmp/opt-loop/runs/{target_id}/{phase}/sample-{sample_index}-hotspots.json"
                ))
            },
            PathBuf::from,
        );

        let alloc_sample_rate = env::var(ENV_ALLOC_SAMPLE_RATE)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_ALLOC_SAMPLE_RATE);

        let stack_depth = env::var(ENV_STACK_DEPTH)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_STACK_DEPTH);

        let state = Self {
            config: ProbeConfig {
                target_id,
                phase,
                sample_index,
                sample_file,
                hotspot_file,
                alloc_sample_rate,
                stack_depth,
            },
            alloc_count: AtomicU64::new(0),
            alloc_bytes: AtomicU64::new(0),
            live_bytes: AtomicI64::new(0),
            peak_live_bytes: AtomicU64::new(0),
            manager_wall_time_ms: AtomicU64::new(0),
            manager_alloc_count: AtomicU64::new(0),
            manager_alloc_bytes: AtomicU64::new(0),
            storage_calls: AtomicU64::new(0),
            storage_bytes: AtomicU64::new(0),
            queue_calls: AtomicU64::new(0),
            queue_bytes: AtomicU64::new(0),
            pubsub_calls: AtomicU64::new(0),
            pubsub_bytes: AtomicU64::new(0),
            bg_job_calls: AtomicU64::new(0),
            bg_job_bytes: AtomicU64::new(0),
            analytics_calls: AtomicU64::new(0),
            analytics_bytes: AtomicU64::new(0),
            hotspots: Mutex::new(HashMap::new()),
            flush_lock: Mutex::new(()),
        };

        state.flush();
        Some(state)
    }

    pub(crate) fn record_alloc(&self, size: usize) {
        let size_u64 = u64::try_from(size).unwrap_or(0);
        let count = self.alloc_count.fetch_add(1, Ordering::Relaxed) + 1;
        self.alloc_bytes.fetch_add(size_u64, Ordering::Relaxed);
        self.add_live_bytes(i64::try_from(size).unwrap_or(0));

        if count.is_multiple_of(self.config.alloc_sample_rate) {
            self.record_hotspot("alloc", None, size_u64);
        }

        if count.is_multiple_of(FLUSH_EVERY_ALLOC_EVENTS) {
            self.flush();
        }
    }

    pub(crate) fn record_dealloc(&self, size: usize) {
        self.add_live_bytes(-i64::try_from(size).unwrap_or(0));
    }

    pub(crate) fn record_realloc(&self, old_size: usize, new_size: usize) {
        let old_i64 = i64::try_from(old_size).unwrap_or(0);
        let new_i64 = i64::try_from(new_size).unwrap_or(0);
        self.add_live_bytes(new_i64 - old_i64);

        let new_size_u64 = u64::try_from(new_size).unwrap_or(0);
        let count = self.alloc_count.fetch_add(1, Ordering::Relaxed) + 1;
        self.alloc_bytes.fetch_add(new_size_u64, Ordering::Relaxed);

        if count.is_multiple_of(self.config.alloc_sample_rate) {
            self.record_hotspot("alloc", None, new_size_u64);
        }

        if count.is_multiple_of(FLUSH_EVERY_ALLOC_EVENTS) {
            self.flush();
        }
    }

    fn record_component_call(
        &self,
        kind: &'static str,
        operation: &str,
        bytes: u64,
        calls: &AtomicU64,
        total_bytes: &AtomicU64,
    ) {
        calls.fetch_add(1, Ordering::Relaxed);
        total_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.record_hotspot(kind, Some(operation), bytes);
        self.flush();
    }

    pub(crate) fn record_storage_call(&self, operation: &str, bytes: u64) {
        self.record_component_call(
            "storage",
            operation,
            bytes,
            &self.storage_calls,
            &self.storage_bytes,
        );
    }

    pub(crate) fn record_queue_call(&self, operation: &str, bytes: u64) {
        self.record_component_call(
            "queue",
            operation,
            bytes,
            &self.queue_calls,
            &self.queue_bytes,
        );
    }

    pub(crate) fn record_pubsub_call(&self, operation: &str, bytes: u64) {
        self.record_component_call(
            "pubsub",
            operation,
            bytes,
            &self.pubsub_calls,
            &self.pubsub_bytes,
        );
    }

    pub(crate) fn record_bg_job_call(&self, operation: &str, bytes: u64) {
        self.record_component_call(
            "bg_job",
            operation,
            bytes,
            &self.bg_job_calls,
            &self.bg_job_bytes,
        );
    }

    pub(crate) fn record_analytics_call(&self, operation: &str, bytes: u64) {
        self.record_component_call(
            "analytics",
            operation,
            bytes,
            &self.analytics_calls,
            &self.analytics_bytes,
        );
    }

    pub(crate) fn record_hotspot(&self, kind: &str, operation: Option<&str>, bytes: u64) {
        let backtrace = capture_backtrace(self.config.stack_depth);
        let stack_hash = hash_string(&backtrace);
        let key = format!("{kind}:{}:{stack_hash}", operation.unwrap_or("-"));

        if let Ok(mut guard) = self.hotspots.lock() {
            let entry = guard.entry(key).or_insert_with(|| HotspotAggregate {
                kind: kind.to_string(),
                operation: operation.map(ToOwned::to_owned),
                stack_hash: format!("{stack_hash:016x}"),
                count: 0,
                total_bytes: 0,
                sample_backtrace: backtrace.clone(),
            });
            entry.count = entry.count.saturating_add(1);
            entry.total_bytes = entry.total_bytes.saturating_add(bytes);
        }
    }

    pub(crate) fn snapshot(&self) -> ProbeSample {
        let storage_calls_total = self.storage_calls.load(Ordering::Relaxed);
        let queue_calls_total = self.queue_calls.load(Ordering::Relaxed);
        let pubsub_calls_total = self.pubsub_calls.load(Ordering::Relaxed);
        let bg_job_calls_total = self.bg_job_calls.load(Ordering::Relaxed);
        let analytics_calls_total = self.analytics_calls.load(Ordering::Relaxed);

        ProbeSample {
            target_id: self.config.target_id.clone(),
            phase: self.config.phase.clone(),
            sample_index: self.config.sample_index,
            timestamp_unix_ms: now_unix_ms(),
            process_id: std::process::id(),
            wall_time_ms: 0,
            manager_wall_time_ms: self.manager_wall_time_ms.load(Ordering::Relaxed),
            heap_alloc_count_total: self.alloc_count.load(Ordering::Relaxed),
            heap_alloc_bytes_total: self.alloc_bytes.load(Ordering::Relaxed),
            heap_peak_live_bytes: self.peak_live_bytes.load(Ordering::Relaxed),
            manager_heap_alloc_count_total: self.manager_alloc_count.load(Ordering::Relaxed),
            manager_heap_alloc_bytes_total: self.manager_alloc_bytes.load(Ordering::Relaxed),
            external_pause_count_total: storage_calls_total
                .saturating_add(queue_calls_total)
                .saturating_add(pubsub_calls_total)
                .saturating_add(bg_job_calls_total)
                .saturating_add(analytics_calls_total),
            storage_calls_total,
            storage_bytes_total: self.storage_bytes.load(Ordering::Relaxed),
            queue_calls_total,
            queue_bytes_total: self.queue_bytes.load(Ordering::Relaxed),
            pubsub_calls_total,
            pubsub_bytes_total: self.pubsub_bytes.load(Ordering::Relaxed),
            bg_job_calls_total,
            bg_job_bytes_total: self.bg_job_bytes.load(Ordering::Relaxed),
            analytics_calls_total,
            analytics_bytes_total: self.analytics_bytes.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn flush(&self) {
        let Ok(_flush_guard) = self.flush_lock.lock() else {
            return;
        };

        if let Some(parent) = self.config.sample_file.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Some(parent) = self.config.hotspot_file.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let snapshot = self.snapshot();
        let should_preserve_existing_sample = snapshot.is_empty()
            && load_sample_if_present(&self.config.sample_file)
                .is_some_and(|existing| !existing.is_empty());
        if !should_preserve_existing_sample && let Ok(bytes) = serde_json::to_vec_pretty(&snapshot)
        {
            let _ = fs::write(&self.config.sample_file, bytes);
        }

        if let Ok(guard) = self.hotspots.lock() {
            let mut records: Vec<HotspotRecord> =
                guard.values().map(HotspotAggregate::to_record).collect();
            records.sort_by(|a, b| {
                b.count
                    .cmp(&a.count)
                    .then_with(|| b.total_bytes.cmp(&a.total_bytes))
            });
            let should_preserve_existing_hotspots = records.is_empty()
                && load_hotspots_if_present(&self.config.hotspot_file)
                    .is_some_and(|existing| !existing.is_empty());
            if !should_preserve_existing_hotspots
                && let Ok(bytes) = serde_json::to_vec_pretty(&records)
            {
                let _ = fs::write(&self.config.hotspot_file, bytes);
            }
        }
    }

    fn reset(&self) {
        self.alloc_count.store(0, Ordering::Relaxed);
        self.alloc_bytes.store(0, Ordering::Relaxed);
        self.live_bytes.store(0, Ordering::Relaxed);
        self.peak_live_bytes.store(0, Ordering::Relaxed);
        self.manager_wall_time_ms.store(0, Ordering::Relaxed);
        self.manager_alloc_count.store(0, Ordering::Relaxed);
        self.manager_alloc_bytes.store(0, Ordering::Relaxed);
        self.storage_calls.store(0, Ordering::Relaxed);
        self.storage_bytes.store(0, Ordering::Relaxed);
        self.queue_calls.store(0, Ordering::Relaxed);
        self.queue_bytes.store(0, Ordering::Relaxed);
        self.pubsub_calls.store(0, Ordering::Relaxed);
        self.pubsub_bytes.store(0, Ordering::Relaxed);
        self.bg_job_calls.store(0, Ordering::Relaxed);
        self.bg_job_bytes.store(0, Ordering::Relaxed);
        self.analytics_calls.store(0, Ordering::Relaxed);
        self.analytics_bytes.store(0, Ordering::Relaxed);
        if let Ok(mut hotspots) = self.hotspots.lock() {
            hotspots.clear();
        }
        self.flush();
    }

    fn add_live_bytes(&self, delta: i64) {
        let new_live = self.live_bytes.fetch_add(delta, Ordering::Relaxed) + delta;
        if new_live <= 0 {
            return;
        }

        let new_live_u64 = u64::try_from(new_live).unwrap_or(0);
        let mut current_peak = self.peak_live_bytes.load(Ordering::Relaxed);
        while new_live_u64 > current_peak {
            match self.peak_live_bytes.compare_exchange(
                current_peak,
                new_live_u64,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current_peak = observed,
            }
        }
    }

    fn counter_snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            alloc_count: self.alloc_count.load(Ordering::Relaxed),
            alloc_bytes: self.alloc_bytes.load(Ordering::Relaxed),
        }
    }

    fn record_manager_measurement(&self, duration_ms: u64, before: CounterSnapshot) {
        let after = self.counter_snapshot();
        self.manager_wall_time_ms
            .store(duration_ms, Ordering::Relaxed);
        self.manager_alloc_count.store(
            after.alloc_count.saturating_sub(before.alloc_count),
            Ordering::Relaxed,
        );
        self.manager_alloc_bytes.store(
            after.alloc_bytes.saturating_sub(before.alloc_bytes),
            Ordering::Relaxed,
        );
        self.flush();
    }
}

#[derive(Clone, Copy)]
struct CounterSnapshot {
    alloc_count: u64,
    alloc_bytes: u64,
}

fn now_unix_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        Err(_) => 0,
    }
}

pub(crate) fn load_sample_if_present(path: &Path) -> Option<ProbeSample> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub(crate) fn load_hotspots_if_present(path: &Path) -> Option<Vec<HotspotRecord>> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn hash_string(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn capture_backtrace(max_lines: usize) -> String {
    let rendered = format!("{:?}", Backtrace::force_capture());
    let mut lines = rendered.lines();
    let mut output = String::new();

    let _ = lines.next();
    for line in lines.take(max_lines) {
        output.push_str(line);
        output.push('\n');
    }

    if output.trim().is_empty() {
        rendered
    } else {
        output
    }
}

fn env_truthy(key: &str) -> bool {
    env::var(key).ok().is_some_and(|value| {
        let normalized = value.trim().to_ascii_lowercase();
        matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
    })
}

fn with_probe_guard<F>(f: F)
where F: FnOnce() {
    IN_PROBE.with(|flag| {
        if flag.get() {
            return;
        }
        flag.set(true);
        f();
        flag.set(false);
    });
}

fn state() -> Option<&'static ProbeState> {
    static STATE: OnceLock<Option<ProbeState>> = OnceLock::new();
    STATE.get_or_init(ProbeState::from_env).as_ref()
}

#[must_use]
pub fn is_enabled() -> bool {
    state().is_some()
}

pub fn force_flush() {
    with_probe_guard(|| {
        if let Some(state) = state() {
            state.flush();
        }
    });
}

pub fn reset() {
    with_probe_guard(|| {
        if let Some(state) = state() {
            state.reset();
        }
    });
}

pub async fn measure_future<Fut>(future: Fut) -> Fut::Output
where Fut: std::future::Future {
    let Some(probe_state) = state() else {
        return future.await;
    };
    let before = probe_state.counter_snapshot();
    let started = Instant::now();
    let output = future.await;
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    with_probe_guard(|| {
        probe_state.record_manager_measurement(duration_ms, before);
    });
    output
}

pub fn record_storage_call(operation: &str, bytes: u64) {
    with_probe_guard(|| {
        if let Some(state) = state() {
            state.record_storage_call(operation, bytes);
        }
    });
}

pub fn record_queue_call(operation: &str, bytes: u64) {
    with_probe_guard(|| {
        if let Some(state) = state() {
            state.record_queue_call(operation, bytes);
        }
    });
}

pub fn record_pubsub_call(operation: &str, bytes: u64) {
    with_probe_guard(|| {
        if let Some(state) = state() {
            state.record_pubsub_call(operation, bytes);
        }
    });
}

pub fn record_bg_job_call(operation: &str, bytes: u64) {
    with_probe_guard(|| {
        if let Some(state) = state() {
            state.record_bg_job_call(operation, bytes);
        }
    });
}

pub fn record_analytics_call(operation: &str, bytes: u64) {
    with_probe_guard(|| {
        if let Some(state) = state() {
            state.record_analytics_call(operation, bytes);
        }
    });
}

pub fn estimate_json_bytes<T: Serialize>(value: &T) -> u64 {
    serde_json::to_vec(value)
        .ok()
        .and_then(|bytes| u64::try_from(bytes.len()).ok())
        .unwrap_or(0)
}

pub struct ProbeAllocator {
    inner: MiMalloc,
}

impl ProbeAllocator {
    #[must_use]
    pub const fn new() -> Self {
        Self { inner: MiMalloc }
    }
}

impl Default for ProbeAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: This allocator delegates all memory operations directly to MiMalloc.
unsafe impl GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.inner.alloc(layout) };
        if !ptr.is_null() {
            with_probe_guard(|| {
                if let Some(state) = state() {
                    state.record_alloc(layout.size());
                }
            });
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        with_probe_guard(|| {
            if let Some(state) = state() {
                state.record_dealloc(layout.size());
            }
        });
        unsafe { self.inner.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { self.inner.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            with_probe_guard(|| {
                if let Some(state) = state() {
                    state.record_realloc(layout.size(), new_size);
                }
            });
        }
        new_ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.inner.alloc_zeroed(layout) };
        if !ptr.is_null() {
            with_probe_guard(|| {
                if let Some(state) = state() {
                    state.record_alloc(layout.size());
                }
            });
        }
        ptr
    }
}
