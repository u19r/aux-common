//! Bounded due-index scans used to reconcile wake hints.

use std::num::{NonZeroU32, NonZeroUsize};

use crate::{
    codec::{KeyCodec, ValueTag},
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    keys,
    store::{
        JobStore, RangeDirection, RangeRequest, RangeRequestInput, StoreCapabilities, StoreKey,
    },
    time::Timestamp,
    transition::constants::{MAX_DUE_RANGE_PAGES, MAX_INDEX_RANGE_BYTES, MAX_INDEX_RANGE_ITEMS},
};

#[derive(Clone, Copy)]
pub(crate) struct RangeLimits {
    pub(crate) item_limit: NonZeroU32,
    pub(crate) byte_limit: NonZeroUsize,
}

/// Applies the library, backend, and remaining-call budgets in one place.
/// Callers pass remaining values so a continuation can never request more
/// than the aggregate discovery budget still available to it.
pub(crate) fn bounded_range_limits(
    capabilities: StoreCapabilities,
    requested_items: NonZeroU32,
    remaining_items: usize,
    remaining_bytes: usize,
) -> Option<RangeLimits> {
    let item_limit = remaining_items
        .min(MAX_INDEX_RANGE_ITEMS)
        .min(requested_items.get() as usize)
        .min(capabilities.max_range_items().get() as usize);
    let byte_limit = remaining_bytes
        .min(MAX_INDEX_RANGE_BYTES)
        .min(capabilities.max_range_bytes().get());
    Some(RangeLimits {
        item_limit: NonZeroU32::new(u32::try_from(item_limit).ok()?)?,
        byte_limit: NonZeroUsize::new(byte_limit)?,
    })
}

pub(super) struct DueScan {
    pub(super) next: Option<Timestamp>,
    pub(super) complete: bool,
}

pub(super) async fn next_due<S: JobStore>(
    system: &JobSystem<S>,
    queue: &crate::ids::QueueName,
    skip: Option<&StoreKey>,
    include: Option<&StoreKey>,
) -> JobResult<DueScan, S::Error> {
    let prefix = keys::due_queue_prefix(system.namespace(), queue)?;
    let end = KeyCodec::prefix_end(&prefix);
    let request = DueScanRequest {
        prefix: &prefix,
        end,
        skip,
        include,
    };
    let mut scan = scan_due_pages(system, request).await?;
    if let Some(include) = include {
        scan.next = merge_included_due(system, queue, include, scan.next)?;
    }
    Ok(DueScan {
        next: scan.next,
        complete: scan.complete,
    })
}

struct DueScanRequest<'a> {
    prefix: &'a StoreKey,
    end: Option<StoreKey>,
    skip: Option<&'a StoreKey>,
    include: Option<&'a StoreKey>,
}

struct DuePageScan {
    next: Option<Timestamp>,
    complete: bool,
    continuation: Option<StoreKey>,
    remaining_items: usize,
    remaining_bytes: usize,
}

impl DuePageScan {
    fn new() -> Self {
        Self {
            next: None,
            complete: false,
            continuation: None,
            remaining_items: MAX_INDEX_RANGE_ITEMS,
            remaining_bytes: MAX_INDEX_RANGE_BYTES,
        }
    }

    fn limits(&self, capabilities: StoreCapabilities) -> Option<RangeLimits> {
        let requested_items = NonZeroU32::new(MAX_INDEX_RANGE_ITEMS as u32)?;
        bounded_range_limits(
            capabilities,
            requested_items,
            self.remaining_items,
            self.remaining_bytes,
        )
    }

    fn fits(&self, item_count: usize, total_bytes: usize) -> bool {
        item_count <= self.remaining_items && total_bytes <= self.remaining_bytes
    }

    fn accept(
        &mut self,
        item_count: usize,
        total_bytes: usize,
        continuation: Option<StoreKey>,
        next: Option<Timestamp>,
    ) -> bool {
        self.remaining_items = self.remaining_items.saturating_sub(item_count);
        self.remaining_bytes = self.remaining_bytes.saturating_sub(total_bytes);
        self.next = merge_timestamps(self.next, next);
        let Some(continuation) = continuation else {
            self.complete = true;
            return false;
        };
        if self.continuation.as_ref() == Some(&continuation) {
            return false;
        }
        self.continuation = Some(continuation);
        true
    }
}

async fn scan_due_pages<S: JobStore>(
    system: &JobSystem<S>,
    request: DueScanRequest<'_>,
) -> JobResult<DuePageScan, S::Error> {
    let mut scan = DuePageScan::new();
    for _ in 0..MAX_DUE_RANGE_PAGES {
        let Some(limits) = scan.limits(system.store().capabilities()) else {
            break;
        };
        let page = read_due_page(
            system,
            request.prefix,
            request.end.clone(),
            scan.continuation.clone(),
            limits,
        )
        .await?;
        let item_count = page.entries.len();
        let total_bytes = page.total_bytes();
        if !scan.fits(item_count, total_bytes) {
            break;
        }
        let next = scan_due_entries(system, &page, request.skip, request.include)?;
        if !scan.accept(item_count, total_bytes, page.continuation.clone(), next) {
            break;
        }
    }
    Ok(scan)
}

async fn read_due_page<S: JobStore>(
    system: &JobSystem<S>,
    prefix: &StoreKey,
    end: Option<StoreKey>,
    continuation: Option<StoreKey>,
    limits: RangeLimits,
) -> JobResult<crate::store::RangePage, S::Error> {
    system
        .store()
        .read_range(RangeRequest::try_from(RangeRequestInput {
            start: Some(prefix.clone()),
            end,
            direction: RangeDirection::Forward,
            item_limit: limits.item_limit,
            byte_limit: limits.byte_limit,
            continuation,
        })?)
        .await
        .map_err(JobSystemError::Store)
}

fn scan_due_entries<S: JobStore>(
    system: &JobSystem<S>,
    page: &crate::store::RangePage,
    skip: Option<&StoreKey>,
    include: Option<&StoreKey>,
) -> JobResult<Option<Timestamp>, S::Error> {
    let mut next = None;
    for entry in &page.entries {
        if skip.is_some_and(|key| key == &entry.key) || include.is_some_and(|key| key == &entry.key)
        {
            continue;
        }
        let decoded = match keys::decode_due_key(system.namespace(), &entry.key) {
            Ok(Some(decoded)) => decoded,
            Ok(None) => continue,
            Err(_) => {
                observe_due_corruption(system);
                continue;
            }
        };
        let timestamp = match keys::decode_timestamp_value(&entry.value, ValueTag::Due) {
            Ok(timestamp) => timestamp,
            Err(_) => {
                observe_due_corruption(system);
                continue;
            }
        };
        if timestamp != decoded.when {
            observe_due_corruption(system);
            continue;
        }
        next = Some(next.map_or(timestamp, |current: Timestamp| current.min(timestamp)));
    }
    Ok(next)
}

fn merge_timestamps(current: Option<Timestamp>, next: Option<Timestamp>) -> Option<Timestamp> {
    match (current, next) {
        (Some(current), Some(next)) => Some(current.min(next)),
        (current, next) => current.or(next),
    }
}

fn observe_due_corruption<S: JobStore>(system: &JobSystem<S>) {
    system.observe_error(crate::observer::SafeJobErrorEvent {
        kind: crate::observer::SafeJobErrorKind::PayloadCorrupt,
        queue: None,
        effect_mode: None,
    });
}

fn merge_included_due<S: JobStore>(
    system: &JobSystem<S>,
    queue: &crate::ids::QueueName,
    include: &StoreKey,
    next: Option<Timestamp>,
) -> JobResult<Option<Timestamp>, S::Error> {
    let Some(entry_due) = keys::decode_due_key(system.namespace(), include)? else {
        return Ok(next);
    };
    if entry_due.queue != queue.as_str() {
        return Ok(next);
    }
    Ok(Some(next.map_or(entry_due.when, |current| {
        current.min(entry_due.when)
    })))
}
