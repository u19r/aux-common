//! Durable schedule cursor controls and generation checks.

use crate::time::Timestamp;

/// Durable cursor state supplied by a caller-owned schedule record.
///
/// The initial `enabled` value comes from
/// [`crate::schedule::RecurringSchedule::enabled`]; after creation, controls
/// mutate this cursor state rather than the definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleCursor {
    pub(super) next_due: Option<Timestamp>,
    pub(super) watermark: Option<Timestamp>,
    pub(super) revision: u64,
    pub(super) generation: u32,
    pub(super) paused: bool,
    pub(super) enabled: bool,
    pub(super) active: bool,
    pub(super) last_intended: Option<Timestamp>,
}

impl ScheduleCursor {
    pub fn new(next_due: Option<Timestamp>, enabled: bool) -> Self {
        Self {
            next_due,
            watermark: None,
            revision: 0,
            generation: 0,
            paused: false,
            enabled,
            active: false,
            last_intended: None,
        }
    }

    pub const fn next_due(&self) -> Option<Timestamp> {
        self.next_due
    }

    pub const fn watermark(&self) -> Option<Timestamp> {
        self.watermark
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub const fn is_paused(&self) -> bool {
        self.paused
    }

    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub const fn last_intended(&self) -> Option<Timestamp> {
        self.last_intended
    }

    pub fn apply_control(
        &mut self,
        expected_revision: u64,
        expected_generation: u32,
        control: ScheduleControl,
    ) -> ScheduleControlResult {
        if expected_revision != self.revision || expected_generation != self.generation {
            return ScheduleControlResult::Conflict {
                revision: self.revision,
                generation: self.generation,
            };
        }
        match control {
            ScheduleControl::Pause => self.paused = true,
            ScheduleControl::Resume => self.paused = false,
            ScheduleControl::Enable => self.enabled = true,
            ScheduleControl::Disable => self.enabled = false,
        }
        self.active = false;
        self.revision = self.revision.saturating_add(1);
        self.generation = self.generation.saturating_add(1);
        ScheduleControlResult::Applied {
            revision: self.revision,
            generation: self.generation,
        }
    }

    pub fn mark_started(&mut self, generation: u32, revision: u64) -> bool {
        if generation != self.generation
            || revision != self.revision
            || self.paused
            || !self.enabled
            || self.active
        {
            return false;
        }
        self.active = true;
        self.revision = self.revision.saturating_add(1);
        true
    }

    pub fn mark_completed(&mut self, generation: u32, revision: u64) -> bool {
        if generation != self.generation || revision != self.revision || !self.active {
            return false;
        }
        self.active = false;
        self.revision = self.revision.saturating_add(1);
        true
    }
}

/// A schedule control mutation whose expected version is checked atomically
/// by a caller-owned schedule record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleControl {
    Pause,
    Resume,
    Enable,
    Disable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleControlResult {
    Applied { revision: u64, generation: u32 },
    Conflict { revision: u64, generation: u32 },
}
