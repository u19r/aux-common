use std::{
    sync::{Arc, Mutex, atomic::AtomicU64},
    time::{Duration, Instant},
};

use crate::{
    batch::{PreparationLimits, RecordCodec, WriteBatch},
    buffer::{BufferSnapshot, WriteBuffer},
    configuration::{
        BufferCapacity, DeliveryPolicy, FlushPolicy, Namespace, SinkLimits, TenantScope,
    },
    constants::DEFAULT_RETRY_MAX_DELAY,
    observer::{
        Clock, DeliveryMode, DrainReport, FlushReport, SinkHealth, WriteEvent, WriteObserver,
    },
    queue::WriteQueue,
    write_sink::WriteSink,
};

#[derive(Default)]
pub(super) struct PolicyState {
    pub(super) mode: DeliveryMode,
    pub(super) health: SinkHealth,
    mode_revision: u64,
    health_revision: u64,
    pub(super) consecutive_failures: u32,
    pub(super) recovery_successes: u32,
    pub(super) probe_exponent: u32,
    pub(super) next_probe_at: Option<Instant>,
    pub(super) completed_drain: Option<DrainReport>,
    pub(super) driver_attached: bool,
}

impl PolicyState {
    pub(super) fn change_mode(&mut self, target: DeliveryMode) -> Option<WriteEvent> {
        if self.mode == target {
            return None;
        }
        let from = std::mem::replace(&mut self.mode, target);
        self.mode_revision = self.mode_revision.saturating_add(1);
        Some(WriteEvent::ModeChanged {
            from,
            to: target,
            revision: self.mode_revision,
        })
    }

    pub(super) fn change_health(&mut self, target: SinkHealth) -> Option<WriteEvent> {
        if self.health == target {
            return None;
        }
        let from = std::mem::replace(&mut self.health, target);
        self.health_revision = self.health_revision.saturating_add(1);
        Some(WriteEvent::HealthChanged {
            from,
            to: target,
            revision: self.health_revision,
        })
    }
}

pub(crate) type ScopeExtractor<T> =
    Arc<dyn Fn(&T) -> Result<TenantScope, crate::WriteError> + Send + Sync>;

pub(crate) struct EngineConfig<T> {
    pub scope_extractor: Option<ScopeExtractor<T>>,
    pub namespace: Namespace,
    pub codec: Arc<dyn RecordCodec<T>>,
    pub batch_strategy: Arc<dyn WriteBatch<T>>,
    pub buffer: Arc<dyn WriteBuffer>,
    pub sink: Arc<dyn WriteSink<T>>,
    pub queue: Option<Arc<dyn WriteQueue>>,
    pub flush_policy: Arc<dyn FlushPolicy>,
    pub capacity: BufferCapacity,
    pub delivery_policy: DeliveryPolicy,
    pub effective_limits: SinkLimits,
    pub preparation: PreparationLimits,
    pub clock: Arc<dyn Clock>,
    pub observer: Arc<dyn WriteObserver>,
    pub periodic_interval: Option<Duration>,
}

pub(crate) struct Engine<T> {
    pub(crate) cfg: EngineConfig<T>,
    pub(super) admission_turn: futures_util::lock::Mutex<()>,
    pub(super) admissions: super::admission_gate::AdmissionGate,
    pub(crate) flush_signal: super::flush_signal::FlushSignal,
    pub(super) drain_deadline: super::deadline::DrainDeadline,
    pub(crate) default_scope: TenantScope,
    pub(super) state: Mutex<PolicyState>,
    pub(super) turn_lock: futures_util::lock::Mutex<()>,
    pub(super) inspection_revision: AtomicU64,
}

impl<T: Send + Sync + 'static> Engine<T> {
    pub(crate) fn new(cfg: EngineConfig<T>) -> Self {
        let default_scope = TenantScope::from_namespace(&cfg.namespace);
        Self {
            cfg,
            admission_turn: futures_util::lock::Mutex::new(()),
            admissions: super::admission_gate::AdmissionGate::default(),
            flush_signal: super::flush_signal::FlushSignal::default(),
            drain_deadline: super::deadline::DrainDeadline::default(),
            default_scope,
            state: Mutex::new(PolicyState::default()),
            turn_lock: futures_util::lock::Mutex::new(()),
            inspection_revision: AtomicU64::new(0),
        }
    }

    pub(crate) fn claim_driver_slot(&self) -> bool {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.driver_attached {
            return false;
        }
        guard.driver_attached = true;
        true
    }

    pub(crate) fn mode_and_health(&self) -> (DeliveryMode, SinkHealth) {
        self.state
            .lock()
            .map_or((DeliveryMode::Buffered, SinkHealth::Closed), |g| {
                (g.mode, g.health)
            })
    }

    pub(super) fn record_sink_success(&self) {
        let mut health_change = None;
        if let Ok(mut guard) = self.state.lock() {
            match guard.health {
                SinkHealth::Closed => guard.consecutive_failures = 0,
                // Only acquire_sink_permission may admit a recovery canary.
                SinkHealth::Open => return,
                SinkHealth::HalfOpen => {
                    guard.consecutive_failures = 0;
                    guard.recovery_successes = guard.recovery_successes.saturating_add(1);
                    if guard.recovery_successes
                        >= self.cfg.delivery_policy.recovery_success_threshold
                    {
                        health_change = guard.change_health(SinkHealth::Closed);
                        guard.probe_exponent = 0;
                        guard.next_probe_at = None;
                    }
                }
            }
        }
        if let Some(event) = health_change {
            self.cfg.observer.observe(event);
        }
    }

    pub(super) fn record_sink_failure(&self, batch_age: Duration) {
        let now = self.cfg.clock.now_instant();
        let mut health_change = None;
        if let Ok(mut guard) = self.state.lock() {
            guard.consecutive_failures = guard.consecutive_failures.saturating_add(1);
            guard.recovery_successes = 0;
            if guard.health != SinkHealth::Closed
                || guard.consecutive_failures >= self.cfg.delivery_policy.failure_threshold
                || batch_age >= self.cfg.delivery_policy.fallback_age
            {
                health_change = guard.change_health(SinkHealth::Open);
                let factor = 1_u32 << guard.probe_exponent.min(10);
                let delay = self
                    .cfg
                    .delivery_policy
                    .probe_initial_delay
                    .saturating_mul(factor)
                    .min(self.cfg.delivery_policy.probe_max_delay);
                guard.probe_exponent = guard.probe_exponent.saturating_add(1);
                guard.next_probe_at = now.checked_add(delay);
            }
        }
        if let Some(event) = health_change {
            self.cfg.observer.observe(event);
        }
    }

    pub(super) fn maybe_restore_buffered_mode(&self, low_watermark_reached: bool) {
        if !low_watermark_reached {
            return;
        }
        let mut mode_change = None;
        if let Ok(mut guard) = self.state.lock()
            && guard.mode == DeliveryMode::Synchronous
            && guard.health == SinkHealth::Closed
        {
            mode_change = guard.change_mode(DeliveryMode::Buffered);
        }
        if let Some(event) = mode_change {
            self.cfg.observer.observe(event);
        }
    }

    pub(super) fn transition_mode(&self, target: DeliveryMode) {
        let mut changed = None;
        if let Ok(mut guard) = self.state.lock()
            && guard.mode == DeliveryMode::Buffered
            && target == DeliveryMode::Synchronous
        {
            changed = guard.change_mode(target);
        }
        if let Some(event) = changed {
            self.cfg.observer.observe(event);
        }
    }

    pub(super) fn transition_health(&self, target: SinkHealth) {
        let mut changed = None;
        if let Ok(mut guard) = self.state.lock() {
            changed = guard.change_health(target);
        }
        if let Some(event) = changed {
            self.cfg.observer.observe(event);
        }
    }

    pub(super) fn retry_delay(&self, attempt_idx: u32) -> Duration {
        self.cfg
            .delivery_policy
            .retry_base_delay
            .saturating_mul(1_u32 << attempt_idx.min(6))
            .min(DEFAULT_RETRY_MAX_DELAY)
    }

    pub(super) fn empty_report(&self) -> FlushReport {
        let (mode, sink_health) = self.mode_and_health();
        FlushReport {
            mode,
            sink_health,
            ..FlushReport::default()
        }
    }

    pub(super) fn empty_snapshot(&self) -> BufferSnapshot {
        BufferSnapshot {
            reclaimable_bytes: 0,
            admission: None,
            stats: Default::default(),
            claimable_open_items: 0,
            claimable_sealed_batches: 0,
            in_flight_batches: 0,
            unsettled_items: 0,
            quarantined_items: 0,
            unresolved_batch_ids: Vec::new(),
            watermark: 0,
            durability: self.cfg.buffer.durability_class(),
        }
    }
}
