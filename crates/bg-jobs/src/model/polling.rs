use std::{sync::atomic::Ordering, time::Duration};

use bytes::Bytes;

use super::{
    ExecutionContext, JobOutcome,
    constants::{MAX_IDLE_POLL_DELAY_MS, POLL_CHECKPOINT_HEADER, POLL_CHECKPOINT_PREFIX_BYTES},
};

impl ExecutionContext<'_> {
    /// Application checkpoint without the durable polling history envelope.
    /// Invalid envelopes remain visible so the application's decoder rejects
    /// them.
    pub fn poll_checkpoint(&self) -> Option<&[u8]> {
        self.checkpoint().map(poll_checkpoint_payload)
    }

    /// Mark a nonempty page of eligible work, including work already applied.
    /// Cloned contexts share this signal; checkpointed pages retain it until
    /// the cycle ends.
    pub fn record_poll_work_found(&self) {
        self.poll_work_found.store(true, Ordering::Relaxed);
    }

    /// Continue a bounded poll page or begin its next cycle. Empty cycles
    /// exponentially back off to five minutes (or the configured base if
    /// longer), with deterministic 80–100 percent jitter. Finding work
    /// resets the delay.
    pub fn continue_poll(
        &self,
        checkpoint: Bytes,
        delay: Duration,
        cycle_complete: bool,
    ) -> Result<JobOutcome, crate::ValidationError> {
        if checkpoint
            .len()
            .saturating_add(POLL_CHECKPOINT_PREFIX_BYTES)
            > super::MAX_CHECKPOINT_BYTES
        {
            return Err(crate::ValidationError::InvalidValue {
                field: "poll checkpoint bytes",
            });
        }
        let (mut empty_cycles, previous_work, _) = self
            .checkpoint()
            .and_then(decode_poll_checkpoint)
            .unwrap_or((0, false, &[]));
        let found_work = previous_work || self.poll_work_found.load(Ordering::Relaxed);
        let delay = if cycle_complete {
            empty_cycles = if found_work {
                0
            } else {
                empty_cycles.saturating_add(1)
            };
            self.idle_poll_delay(delay, empty_cycles)
        } else {
            delay
        };
        let mut encoded = Vec::with_capacity(POLL_CHECKPOINT_PREFIX_BYTES + checkpoint.len());
        encoded.extend_from_slice(POLL_CHECKPOINT_HEADER);
        encoded.extend_from_slice(&empty_cycles.to_be_bytes());
        encoded.push(u8::from(!cycle_complete && found_work));
        encoded.extend_from_slice(&checkpoint);
        Ok(JobOutcome::Continue {
            not_before: self.wall_now().checked_add(delay)?,
            checkpoint: Bytes::from(encoded),
        })
    }

    fn idle_poll_delay(&self, base: Duration, empty_cycles: u32) -> Duration {
        let base_ms = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
        let cap = MAX_IDLE_POLL_DELAY_MS.max(base_ms);
        let delay = base_ms
            .saturating_mul(1u64 << empty_cycles.min(32))
            .min(cap);
        let entropy = self
            .job_id()
            .as_bytes()
            .iter()
            .fold(self.wall_now().as_millis() as u64, |seed, byte| {
                seed.wrapping_mul(31).wrapping_add(u64::from(*byte))
            });
        Duration::from_millis((u128::from(delay) * u128::from(80 + entropy % 21) / 100) as u64)
    }
}

fn decode_poll_checkpoint(bytes: &[u8]) -> Option<(u32, bool, &[u8])> {
    if bytes.len() < POLL_CHECKPOINT_PREFIX_BYTES || !bytes.starts_with(POLL_CHECKPOINT_HEADER) {
        return None;
    }
    let empty_cycles = u32::from_be_bytes(bytes[8..12].try_into().ok()?);
    let found_work = match bytes[12] {
        0 => false,
        1 => true,
        _ => return None,
    };
    Some((
        empty_cycles,
        found_work,
        &bytes[POLL_CHECKPOINT_PREFIX_BYTES..],
    ))
}

/// Decode the application bytes from a polling continuation checkpoint.
/// Non-polling and invalid envelopes remain unchanged for the caller's decoder.
pub fn poll_checkpoint_payload(bytes: &[u8]) -> &[u8] {
    decode_poll_checkpoint(bytes).map_or(bytes, |(_, _, payload)| payload)
}
