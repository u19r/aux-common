use std::{future::Future, num::NonZeroUsize, time::Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RefreshDemand {
    Cold,
    Background,
}

impl RefreshDemand {
    /// Physical adapters inherit demand, including promotion of outer cache
    /// flights.
    pub fn current() -> Self {
        crate::RefreshPriority::current().demand()
    }

    pub(super) async fn scope<F: Future>(self, future: F) -> F::Output {
        crate::RefreshPriority::scope(self, future).await
    }
}

/// Scheduling facts, not authority. Deadline checks cannot replace the caller's
/// atomic generation/publication check or durable mutation guards.
#[derive(Clone, Copy)]
pub struct RefreshWork {
    pub(super) deadline: Instant,
    pub(super) bytes: NonZeroUsize,
    pub(super) demand: RefreshDemand,
}

impl RefreshWork {
    pub fn new(deadline: Instant, bytes: NonZeroUsize, demand: RefreshDemand) -> Self {
        Self {
            deadline,
            bytes,
            demand,
        }
    }
}

pub struct RefreshTicket<K> {
    pub(super) key: K,
    pub(super) generation: u64,
    pub(super) work: RefreshWork,
}

impl<K> RefreshTicket<K> {
    pub fn new(key: K, generation: u64, work: RefreshWork) -> Self {
        Self {
            key,
            generation,
            work,
        }
    }

    pub fn key(&self) -> &K {
        &self.key
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn deadline(&self) -> Instant {
        self.work.deadline
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshAdmission {
    Queued,
    Joined,
    Full,
    Oversized,
    Expired,
    Closed,
}
