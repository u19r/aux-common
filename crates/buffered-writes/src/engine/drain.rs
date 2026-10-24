use std::time::Instant;

use super::state::Engine;
use crate::{
    buffer::BufferSnapshot,
    configuration::{Deadline, DurabilityClass},
    constants::DEFAULT_SHUTDOWN_SAFETY_MARGIN,
    observer::{DeliveryMode, DrainReport, FlushReport, WriteEvent},
};

impl<T: Send + Sync + 'static> Engine<T> {
    pub(crate) async fn shutdown(&self, requested_deadline: Deadline) -> DrainReport {
        let now = self.cfg.clock.now_instant();
        let effective_deadline = match self.begin_shutdown_drain(requested_deadline, now) {
            Ok(deadline) => deadline,
            Err(completed) => return completed,
        };
        let started = self.cfg.clock.now_instant();
        let remaining = effective_deadline.remaining_at(started);
        let safety_budget =
            remaining.saturating_sub(DEFAULT_SHUTDOWN_SAFETY_MARGIN.min(remaining / 4));
        let work_deadline = Deadline::from_anchor(started, safety_budget);
        let initial_snapshot = self
            .inspect_now(work_deadline)
            .await
            .unwrap_or_else(|_| self.empty_snapshot());
        let admissions_idle = self
            .complete_engine_operation(work_deadline, || self.admissions.wait_mutations_idle())
            .await
            .is_some();
        self.reconcile_uncertain_admissions(work_deadline).await;
        let flush_report = self.flush_turn(None, true, work_deadline).await;
        let admissions_known = admissions_idle
            && self
                .reconcile_uncertain_admissions(effective_deadline)
                .await;
        let (snapshot, inspection_unknown) = match self.inspect_now(effective_deadline).await {
            Ok(snapshot) => (snapshot, false),
            Err(_) => (initial_snapshot, true),
        };
        self.finish_shutdown_drain(
            started,
            effective_deadline,
            flush_report,
            (snapshot, inspection_unknown || !admissions_known),
        )
    }

    fn finish_shutdown_drain(
        &self,
        started: Instant,
        effective_deadline: Deadline,
        flush_report: FlushReport,
        observation: (BufferSnapshot, bool),
    ) -> DrainReport {
        let (snapshot, state_unknown) = observation;
        let volatile_unresolved = if snapshot.durability == DurabilityClass::Volatile {
            snapshot.unsettled_items
        } else {
            0
        };
        let elapsed = self
            .cfg
            .clock
            .now_instant()
            .saturating_duration_since(started);
        let report = DrainReport {
            batches_flushed: flush_report.batches_flushed,
            items_settled: flush_report.items_settled,
            batches_queued: flush_report.batches_queued,
            unresolved_batches: snapshot.unresolved_batch_ids,
            unresolved_admissions: self.admissions.unresolved_ids(),
            unresolved_items: snapshot.unsettled_items,
            volatile_unresolved_items: volatile_unresolved,
            quarantined_items: snapshot.quarantined_items,
            state_unknown,
            completed_before_deadline: !state_unknown
                && snapshot.unsettled_items == 0
                && !effective_deadline.is_expired_at(self.cfg.clock.now_instant()),
            elapsed,
        };
        self.record_completed_drain(&report);
        report
    }

    fn record_completed_drain(&self, report: &DrainReport) {
        let event = self.state.lock().ok().and_then(|mut guard| {
            guard.completed_drain = Some(report.clone());
            guard.change_mode(DeliveryMode::Stopped)
        });
        if let Some(event) = event {
            self.cfg.observer.observe(event);
        }
        self.cfg.observer.observe(WriteEvent::DrainCompleted {
            elapsed: report.elapsed,
            unresolved_items: report.unresolved_items,
            unresolved_batches: report.unresolved_batches.len(),
            state_unknown: report.state_unknown,
            clean: report.is_clean(),
        });
    }

    pub(crate) fn begin_shutdown_drain(
        &self,
        requested: Deadline,
        now: Instant,
    ) -> Result<Deadline, DrainReport> {
        let Ok(mut guard) = self.state.lock() else {
            return Err(DrainReport::default());
        };
        if let Some(done) = &guard.completed_drain {
            return Err(done.clone());
        }
        self.admissions.close();
        let event = if matches!(guard.mode, DeliveryMode::Draining | DeliveryMode::Stopped) {
            None
        } else {
            guard.change_mode(DeliveryMode::Draining)
        };
        let merged = self.drain_deadline.shorten(requested, now);
        drop(guard);
        if let Some(event) = event {
            self.cfg.observer.observe(event);
        }
        Ok(merged)
    }
}
