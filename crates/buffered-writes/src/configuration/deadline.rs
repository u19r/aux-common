use std::time::{Duration, Instant};

/// Finite execution deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Deadline {
    at: Option<Instant>,
    budget: Duration,
}

impl Deadline {
    #[must_use]
    pub fn after(budget: Duration) -> Self {
        Self::from_anchor(Instant::now(), budget)
    }

    #[must_use]
    pub fn at(instant: Instant) -> Self {
        Self {
            at: Some(instant),
            budget: instant.saturating_duration_since(Instant::now()),
        }
    }

    #[must_use]
    pub fn from_anchor(anchor: Instant, budget: Duration) -> Self {
        Self {
            at: anchor.checked_add(budget),
            budget,
        }
    }

    #[must_use]
    pub const fn budget(&self) -> Duration {
        self.budget
    }

    #[must_use]
    pub fn remaining_at(&self, now: Instant) -> Duration {
        self.at
            .map_or(self.budget, |target| target.saturating_duration_since(now))
    }

    #[must_use]
    pub fn is_expired_at(&self, now: Instant) -> bool {
        self.remaining_at(now).is_zero()
    }

    #[must_use]
    pub fn shorten_to(self, other: Self, now: Instant) -> Self {
        if other.remaining_at(now) < self.remaining_at(now) {
            other
        } else {
            self
        }
    }
}

impl From<Duration> for Deadline {
    fn from(duration: Duration) -> Self {
        Self::after(duration)
    }
}

impl From<Instant> for Deadline {
    fn from(instant: Instant) -> Self {
        Self::at(instant)
    }
}
