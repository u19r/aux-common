use std::sync::{Arc, Mutex};

use crate::{GaugeMetric, MetricLabel, MetricsFacade};

/// Replaces one observer's contribution using engine-assigned revisions.
/// A delayed older callback cannot subtract a state this observer never saw.
pub(super) struct StateMetric {
    facade: Arc<dyn MetricsFacade>,
    metric: GaugeMetric,
    key: &'static str,
    labels: &'static [&'static str],
    state: Mutex<(u64, usize)>,
}

impl StateMetric {
    pub(super) fn new(
        facade: Arc<dyn MetricsFacade>,
        metric: GaugeMetric,
        key: &'static str,
        labels: &'static [&'static str],
    ) -> Self {
        facade.increment_gauge(metric, &[MetricLabel::new(key, labels[0])], 1.0);
        Self {
            facade,
            metric,
            key,
            labels,
            state: Mutex::new((0, 0)),
        }
    }

    pub(super) fn observe(&self, revision: u64, index: usize) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if revision <= state.0 {
            return;
        }
        let previous = std::mem::replace(&mut *state, (revision, index));
        if previous.1 == index {
            return;
        }
        self.facade.decrement_gauge(
            self.metric,
            &[MetricLabel::new(self.key, self.labels[previous.1])],
            1.0,
        );
        self.facade.increment_gauge(
            self.metric,
            &[MetricLabel::new(self.key, self.labels[index])],
            1.0,
        );
    }
}

impl Drop for StateMetric {
    fn drop(&mut self) {
        let state = match self.state.get_mut() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.facade.decrement_gauge(
            self.metric,
            &[MetricLabel::new(self.key, self.labels[state.1])],
            1.0,
        );
    }
}
