use std::{
    borrow::Borrow,
    collections::HashMap,
    hash::Hash,
    sync::Arc,
    time::{Duration, Instant},
};

use hashlink::LinkedHashMap;

use crate::{
    RefreshAdmission, RefreshBatch, RefreshDemand, RefreshQueueLimits, RefreshQueueStats,
    RefreshTicket, RefreshWork,
    load_lease::LoadLease,
    refresh_batch::RefreshJob,
    refresh_queue_core::{QueuePoll, RefreshQueueCore},
};

struct QueuedTicket {
    generation: u64,
    work: RefreshWork,
    enqueued: Instant,
}

struct ActiveTicket {
    generation: u64,
    work: RefreshWork,
    batch: u64,
    lease: LoadLease,
}

struct ActiveBatch {
    keys: usize,
    cancelled: usize,
    demand: RefreshDemand,
    cancellation: LoadLease,
}

pub(super) struct QueueState<K: Eq + Hash> {
    cold: LinkedHashMap<K, QueuedTicket>,
    background: LinkedHashMap<K, QueuedTicket>,
    active: HashMap<K, ActiveTicket>,
    batches: HashMap<u64, ActiveBatch>,
    next_batch: u64,
    bytes: usize,
    background_keys: usize,
    background_bytes: usize,
    closed: bool,
}

impl<K: Eq + Hash> QueueState<K> {
    pub(super) fn new() -> Self {
        Self {
            cold: LinkedHashMap::new(),
            background: LinkedHashMap::new(),
            active: HashMap::new(),
            batches: HashMap::new(),
            next_batch: 0,
            bytes: 0,
            background_keys: 0,
            background_bytes: 0,
            closed: false,
        }
    }

    pub(super) fn stats(&self) -> RefreshQueueStats {
        RefreshQueueStats {
            queued_keys: self.cold.len() + self.background.len(),
            active_keys: self.active.len(),
            charged_bytes: self.bytes,
            background_keys: self.background_keys,
            active_batches: self.batches.len(),
            closed: self.closed,
        }
    }

    pub(super) fn close(&mut self) {
        self.closed = true;
        while let Some((_, ticket)) = self.cold.pop_front() {
            self.refund(ticket.work);
        }
        while let Some((_, ticket)) = self.background.pop_front() {
            self.refund(ticket.work);
        }
        for ticket in self.active.values() {
            ticket.lease.cancel();
        }
        for batch in self.batches.values() {
            batch.cancellation.cancel();
        }
    }

    pub(super) fn release_batch(&mut self, id: u64) {
        if self.batches.remove(&id).is_none() {
            return;
        }
        let mut bytes = 0;
        let mut background_keys = 0;
        let mut background_bytes = 0;
        self.active.retain(|_, ticket| {
            if ticket.batch != id {
                return true;
            }
            bytes += ticket.work.bytes.get();
            if ticket.work.demand == RefreshDemand::Background {
                background_keys += 1;
                background_bytes += ticket.work.bytes.get();
            }
            false
        });
        self.bytes -= bytes;
        self.background_keys -= background_keys;
        self.background_bytes -= background_bytes;
    }

    pub(super) fn refund(&mut self, work: RefreshWork) {
        self.bytes -= work.bytes.get();
        if work.demand == RefreshDemand::Background {
            self.background_keys -= 1;
            self.background_bytes -= work.bytes.get();
        }
    }

    pub(super) fn cancel_key(&mut self, key: &K, generation: u64) -> bool {
        let queued = if self
            .cold
            .get(key)
            .is_some_and(|ticket| ticket.generation == generation)
        {
            self.cold.remove(key)
        } else if self
            .background
            .get(key)
            .is_some_and(|ticket| ticket.generation == generation)
        {
            self.background.remove(key)
        } else {
            None
        };
        if let Some(ticket) = queued {
            self.refund(ticket.work);
            return true;
        }
        let Some(ticket) = self.active.get(key) else {
            return false;
        };
        if ticket.generation != generation {
            return false;
        }
        if ticket.lease.is_cancelled() {
            return true;
        }
        ticket.lease.cancel();
        if let Some(batch) = self.batches.get_mut(&ticket.batch) {
            batch.cancelled += 1;
            if batch.cancelled == batch.keys {
                batch.cancellation.cancel();
            }
        }
        true
    }

    pub(super) fn select_demand(
        &self,
        limits: &RefreshQueueLimits,
        collection: Duration,
    ) -> (Option<RefreshDemand>, Option<Instant>) {
        if self.batches.len() >= limits.active_batches {
            return (None, None);
        }
        if let Some((_, ticket)) = self.cold.front() {
            return (Some(RefreshDemand::Cold), Some(ticket.enqueued));
        }
        let background_batches = self
            .batches
            .values()
            .filter(|batch| batch.demand == RefreshDemand::Background)
            .count();
        if background_batches >= limits.active_batches - 1 {
            return (None, None);
        }
        let ready = self
            .background
            .front()
            .and_then(|(_, ticket)| ticket.enqueued.checked_add(collection));
        (ready.map(|_| RefreshDemand::Background), ready)
    }

    fn resident_keys(&self) -> usize {
        self.cold.len() + self.background.len() + self.active.len()
    }

    fn can_reserve(
        &self,
        demand: RefreshDemand,
        keys: usize,
        bytes: usize,
        limits: &RefreshQueueLimits,
    ) -> bool {
        limits
            .total
            .can_reserve(self.resident_keys(), self.bytes, keys, bytes)
            && (demand == RefreshDemand::Cold
                || limits.background.can_reserve(
                    self.background_keys,
                    self.background_bytes,
                    keys,
                    bytes,
                ))
    }

    pub(super) fn promote_cold<Q>(&mut self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        if let Some((key, mut ticket)) = self.background.remove_entry(key) {
            self.background_keys -= 1;
            self.background_bytes -= ticket.work.bytes.get();
            ticket.work.demand = RefreshDemand::Cold;
            self.cold.insert(key, ticket);
            return true;
        }
        false
    }
}

impl<K: Eq + Hash + Clone> QueueState<K> {
    pub(super) fn poll_batch(
        &mut self,
        limits: &RefreshQueueLimits,
        collection: Duration,
        core: Arc<RefreshQueueCore<K>>,
    ) -> QueuePoll<K> {
        let now = Instant::now();
        self.expire_tickets(now);
        if self.closed {
            return QueuePoll::Closed;
        }
        let (demand, ready_at) = self.select_demand(limits, collection);
        if let Some(demand) = demand
            && ready_at.is_some_and(|deadline| deadline <= now)
            && let Some(batch) = self.take_batch(demand, limits, core)
        {
            return QueuePoll::Ready(batch);
        }
        let next = self
            .cold
            .values()
            .chain(self.background.values())
            .map(|ticket| ticket.work.deadline)
            .chain(ready_at.filter(|deadline| *deadline > now))
            .min();
        QueuePoll::Wait(next)
    }

    pub(super) fn expire_tickets(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .cold
            .iter()
            .chain(self.background.iter())
            .filter(|(_, ticket)| ticket.work.deadline <= now)
            .map(|(key, ticket)| (key.clone(), ticket.generation))
            .chain(
                self.active
                    .iter()
                    .filter(|(_, ticket)| ticket.work.deadline <= now)
                    .map(|(key, ticket)| (key.clone(), ticket.generation)),
            )
            .collect();
        for (key, generation) in expired {
            self.cancel_key(&key, generation);
        }
    }

    pub(super) fn admit_ticket(
        &mut self,
        ticket: RefreshTicket<K>,
        limits: &RefreshQueueLimits,
        now: Instant,
    ) -> RefreshAdmission {
        if self.closed {
            return RefreshAdmission::Closed;
        }
        if ticket.work.deadline <= now {
            return RefreshAdmission::Expired;
        }
        if ticket.work.bytes.get() > limits.batch.bytes {
            return RefreshAdmission::Oversized;
        }
        if let Some(outcome) = self.join_ticket(&ticket, limits) {
            return outcome;
        }
        if !self.can_reserve(ticket.work.demand, 1, ticket.work.bytes.get(), limits) {
            return RefreshAdmission::Full;
        }
        self.bytes += ticket.work.bytes.get();
        let pending = if ticket.work.demand == RefreshDemand::Background {
            self.background_keys += 1;
            self.background_bytes += ticket.work.bytes.get();
            &mut self.background
        } else {
            &mut self.cold
        };
        pending.insert(
            ticket.key,
            QueuedTicket {
                generation: ticket.generation,
                work: ticket.work,
                enqueued: now,
            },
        );
        RefreshAdmission::Queued
    }

    fn join_ticket(
        &mut self,
        ticket: &RefreshTicket<K>,
        limits: &RefreshQueueLimits,
    ) -> Option<RefreshAdmission> {
        if let Some(existing) = self
            .cold
            .get(&ticket.key)
            .or_else(|| self.background.get(&ticket.key))
        {
            if existing.generation != ticket.generation {
                return Some(RefreshAdmission::Full);
            }
            return Some(self.merge_queued(&ticket.key, ticket.work, limits));
        }
        if let Some(existing) = self.active.get(&ticket.key) {
            return Some(
                if existing.generation == ticket.generation
                    && !existing.lease.is_cancelled()
                    && ticket.work.deadline >= existing.work.deadline
                    && ticket.work.bytes <= existing.work.bytes
                {
                    RefreshAdmission::Joined
                } else {
                    RefreshAdmission::Full
                },
            );
        }
        None
    }

    fn merge_queued(
        &mut self,
        key: &K,
        work: RefreshWork,
        limits: &RefreshQueueLimits,
    ) -> RefreshAdmission {
        let Some(existing) = self.cold.get(key).or_else(|| self.background.get(key)) else {
            return RefreshAdmission::Full;
        };
        if existing.work.demand == RefreshDemand::Cold
            && work.demand == RefreshDemand::Background
            && work.bytes > existing.work.bytes
        {
            return RefreshAdmission::Full;
        }
        let bytes = existing.work.bytes.max(work.bytes);
        let delta = bytes.get() - existing.work.bytes.get();
        let background = existing.work.demand == RefreshDemand::Background
            && work.demand == RefreshDemand::Background;
        let demand = if background {
            RefreshDemand::Background
        } else {
            RefreshDemand::Cold
        };
        if !self.can_reserve(demand, 0, delta, limits) {
            return RefreshAdmission::Full;
        }
        if work.demand == RefreshDemand::Cold {
            self.promote_cold(key);
        }
        let Some(existing) = self
            .cold
            .get_mut(key)
            .or_else(|| self.background.get_mut(key))
        else {
            return RefreshAdmission::Full;
        };
        existing.work.deadline = existing.work.deadline.min(work.deadline);
        existing.work.bytes = bytes;
        self.bytes += delta;
        if background {
            self.background_bytes += delta;
        }
        RefreshAdmission::Joined
    }

    pub(super) fn take_batch(
        &mut self,
        demand: RefreshDemand,
        limits: &RefreshQueueLimits,
        core: Arc<RefreshQueueCore<K>>,
    ) -> Option<RefreshBatch<K>> {
        while self.batches.contains_key(&self.next_batch) {
            self.next_batch = self.next_batch.wrapping_add(1);
        }
        let id = self.next_batch;
        self.next_batch = self.next_batch.wrapping_add(1);
        let jobs = self.activate_tickets(demand, id, limits.batch);
        let deadline = jobs.iter().map(|job| job.ticket.deadline()).min()?;
        let cancellation = LoadLease::new();
        self.batches.insert(
            id,
            ActiveBatch {
                keys: jobs.len(),
                cancelled: 0,
                demand,
                cancellation: cancellation.clone(),
            },
        );
        Some(RefreshBatch {
            core,
            id,
            jobs,
            cancellation,
            deadline,
        })
    }

    fn activate_tickets(
        &mut self,
        demand: RefreshDemand,
        id: u64,
        budget: crate::RefreshBudget,
    ) -> Vec<RefreshJob<K>> {
        let mut jobs = Vec::new();
        let mut bytes = 0;
        while jobs.len() < budget.keys {
            let Some((key, ticket)) = self.pop_ticket(demand, budget.bytes - bytes) else {
                break;
            };
            bytes += ticket.work.bytes.get();
            jobs.push(self.activate_ticket(key, ticket, id));
        }
        jobs
    }

    fn pop_ticket(
        &mut self,
        demand: RefreshDemand,
        remaining_bytes: usize,
    ) -> Option<(K, QueuedTicket)> {
        let pending = if demand == RefreshDemand::Cold {
            &mut self.cold
        } else {
            &mut self.background
        };
        if pending.front()?.1.work.bytes.get() > remaining_bytes {
            return None;
        }
        pending.pop_front()
    }

    fn activate_ticket(&mut self, key: K, ticket: QueuedTicket, id: u64) -> RefreshJob<K> {
        let lease = LoadLease::new();
        self.active.insert(
            key.clone(),
            ActiveTicket {
                generation: ticket.generation,
                work: ticket.work,
                batch: id,
                lease: lease.clone(),
            },
        );
        RefreshJob {
            ticket: RefreshTicket::new(key, ticket.generation, ticket.work),
            lease,
        }
    }
}
