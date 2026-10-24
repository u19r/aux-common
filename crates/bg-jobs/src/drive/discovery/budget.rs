use super::super::constants::{MAX_DISCOVERY_BYTES, MAX_DISCOVERY_ITEMS};
use crate::{
    store::{RangeEntry, StoreCapabilities, StoreKey},
    transition::{RangeLimits, bounded_range_limits},
};

pub(super) struct DiscoveryBudget {
    remaining_items: usize,
    remaining_bytes: usize,
    observer: std::sync::Arc<dyn crate::observer::JobObserver>,
}

impl DiscoveryBudget {
    pub(super) fn new(observer: std::sync::Arc<dyn crate::observer::JobObserver>) -> Self {
        Self {
            observer,
            remaining_items: MAX_DISCOVERY_ITEMS,
            // Range pages and authoritative record reads share one fixed
            // library-owned allowance. The backend range limit only bounds
            // each request; deriving the aggregate allowance from it would
            // make small range pages starve valid record reads, while a
            // machine-sized backend could otherwise expose an unbounded
            // retained response.
            remaining_bytes: MAX_DISCOVERY_BYTES,
        }
    }

    fn observe_capacity(&self) {
        self.observer
            .observe(crate::observer::JobEvent::CapacityLimited {
                resource: if self.remaining_items == 0 {
                    crate::observer::CapacityResource::DiscoveryItems
                } else {
                    crate::observer::CapacityResource::DiscoveryBytes
                },
            });
    }

    pub(super) fn reserve_entry(&mut self, entry: &RangeEntry) -> bool {
        let entry_bytes = entry.key.as_bytes().len().saturating_add(entry.value.len());
        if self.remaining_items == 0 || entry_bytes > self.remaining_bytes {
            self.observe_capacity();
            return false;
        }
        self.remaining_items = self.remaining_items.saturating_sub(1);
        self.remaining_bytes = self.remaining_bytes.saturating_sub(entry_bytes);
        true
    }

    pub(super) fn range_limits(
        &self,
        capabilities: StoreCapabilities,
        requested_items: std::num::NonZeroU32,
    ) -> Option<RangeLimits> {
        let limits = bounded_range_limits(
            capabilities,
            requested_items,
            self.remaining_items,
            self.remaining_bytes,
        );
        if limits.is_none() {
            self.observe_capacity();
        }
        limits
    }

    pub(super) fn record_batch_len(
        &self,
        keys: &[StoreKey],
        max_value_bytes: usize,
        max_keys: usize,
        max_key_bytes: usize,
    ) -> Option<usize> {
        let mut response_bytes = 0usize;
        let mut key_bytes = 0usize;
        for (index, key) in keys.iter().enumerate() {
            let next_key_bytes = key_bytes.saturating_add(key.as_bytes().len());
            if index >= max_keys || next_key_bytes > max_key_bytes {
                if index == 0 {
                    self.observe_capacity();
                }
                return (index > 0).then_some(index);
            }
            let record_bytes = key.as_bytes().len().saturating_add(max_value_bytes);
            let next = response_bytes.saturating_add(record_bytes);
            if next > self.remaining_bytes {
                if index == 0 {
                    self.observe_capacity();
                }
                return (index > 0).then_some(index);
            }
            key_bytes = next_key_bytes;
            response_bytes = next;
        }
        (!keys.is_empty()).then_some(keys.len())
    }

    pub(super) fn reserve_record_keys(&mut self, keys: &[StoreKey]) {
        let bytes = keys.iter().map(|key| key.as_bytes().len()).sum::<usize>();
        self.remaining_bytes = self.remaining_bytes.saturating_sub(bytes);
    }

    pub(super) fn reserve_record_value(&mut self, bytes: usize) -> bool {
        if bytes > self.remaining_bytes {
            self.observe_capacity();
            return false;
        }
        self.remaining_bytes = self.remaining_bytes.saturating_sub(bytes);
        true
    }

    pub(super) fn is_exhausted(&self) -> bool {
        let exhausted = self.remaining_items == 0 || self.remaining_bytes == 0;
        if exhausted {
            self.observe_capacity();
        }
        exhausted
    }
}
