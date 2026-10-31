use std::sync::{Arc, Mutex};

use buffered_writes::BufferStats;

use crate::{GaugeMetric, MetricsFacade};

struct BufferState {
    revision: u64,
    items: usize,
    bytes: usize,
    unknown: bool,
    terminal: bool,
}

/// Serialize both state and emitted deltas, preserving nonnegative
/// contributions.
pub(super) struct BufferMetric {
    facade: Arc<dyn MetricsFacade>,
    state: Mutex<BufferState>,
}

impl BufferMetric {
    pub(super) fn new(facade: Arc<dyn MetricsFacade>) -> Self {
        facade.increment_gauge(GaugeMetric::BufferedMeteringUnknownBuffers, &[], 1.0);
        Self {
            facade,
            state: Mutex::new(BufferState {
                revision: 0,
                items: 0,
                bytes: 0,
                unknown: true,
                terminal: false,
            }),
        }
    }

    pub(super) fn observe(&self, revision: u64, stats: Option<BufferStats>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.terminal || revision <= state.revision {
            return;
        }
        state.revision = revision;
        let items = stats.map_or(state.items, |stats| stats.items());
        let bytes = stats.map_or(state.bytes, |stats| stats.bytes());
        self.replace_sample(&mut state, items, bytes, stats.is_none());
    }

    /// Deliberately poisons the guarded state (test-only). Regression tests
    /// use this to prove a panicking guarded section cannot disable buffer
    /// gauges for the process lifetime.
    #[cfg(test)]
    pub(super) fn poison_state_for_test(&self) {
        Self::poison_mutex_for_test(&self.state);
    }

    #[cfg(test)]
    fn poison_mutex_for_test<T>(mutex: &Mutex<T>) {
        // The deliberate unwind prints through the installed panic hook; the
        // hook itself is never swapped because swaps are process-global.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = mutex.lock().expect("poison probe must hold the lock");
            panic!("mutex poison probe");
        }));
        assert!(outcome.is_err(), "poison probe must actually unwind");
    }

    pub(super) fn finish(&self, unknown: bool, clean: bool) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.terminal {
            return;
        }
        state.terminal = true;
        let items = if clean { 0 } else { state.items };
        // Clean drains can retain receipt metadata; do not invent zero bytes.
        let bytes = state.bytes;
        self.replace_sample(&mut state, items, bytes, unknown);
    }

    fn replace_sample(&self, state: &mut BufferState, items: usize, bytes: usize, unknown: bool) {
        for (metric, delta) in [
            (
                GaugeMetric::BufferedMeteringObservedItems,
                items as f64 - state.items as f64,
            ),
            (
                GaugeMetric::BufferedMeteringObservedBytes,
                bytes as f64 - state.bytes as f64,
            ),
            (
                GaugeMetric::BufferedMeteringUnknownBuffers,
                f64::from(unknown) - f64::from(state.unknown),
            ),
        ] {
            self.facade.increment_gauge(metric, &[], delta);
        }
        state.items = items;
        state.bytes = bytes;
        state.unknown = unknown;
    }
}

impl Drop for BufferMetric {
    fn drop(&mut self) {
        let state = match self.state.get_mut() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        for (metric, value) in [
            (
                GaugeMetric::BufferedMeteringObservedItems,
                state.items as f64,
            ),
            (
                GaugeMetric::BufferedMeteringObservedBytes,
                state.bytes as f64,
            ),
            (
                GaugeMetric::BufferedMeteringUnknownBuffers,
                f64::from(state.unknown),
            ),
        ] {
            self.facade.decrement_gauge(metric, &[], value);
        }
    }
}
