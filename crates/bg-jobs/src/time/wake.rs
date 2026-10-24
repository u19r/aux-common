//! Advisory wall-clock wake calculations.

use super::Timestamp;

/// An advisory wall-clock wake result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeHint {
    Now,
    At(Timestamp),
    None,
}

impl WakeHint {
    pub const fn from_timestamp(at: Timestamp, now: Timestamp) -> Self {
        if at.as_millis() <= now.as_millis() {
            Self::Now
        } else {
            Self::At(at)
        }
    }

    pub const fn from_optional_timestamp(timestamp: Option<Timestamp>) -> Self {
        match timestamp {
            Some(timestamp) => Self::At(timestamp),
            None => Self::None,
        }
    }

    pub const fn is_now(self) -> bool {
        matches!(self, Self::Now)
    }

    pub const fn earliest(self, candidate: Self) -> Self {
        match (self, candidate) {
            (Self::Now, _) | (_, Self::Now) => Self::Now,
            (Self::None, other) | (other, Self::None) => other,
            (Self::At(current), Self::At(candidate)) => {
                if current.as_millis() <= candidate.as_millis() {
                    Self::At(current)
                } else {
                    Self::At(candidate)
                }
            }
        }
    }
}
