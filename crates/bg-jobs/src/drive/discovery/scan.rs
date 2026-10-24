use super::{
    super::{claim_deadline_reached, constants::OperationBudget},
    budget::DiscoveryBudget,
};
use crate::{
    budget::{DriveRequest, DriveStopReason},
    codec::{KeyCodec, KeyTag},
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    ids::QueueName,
    keys,
    store::{JobStore, RangeDirection, RangePage, RangeRequest, RangeRequestInput, StoreKey},
    time::MonotonicDeadline,
    transition::RangeLimits,
};

pub(super) struct QueueDiscovery {
    pub(super) due_entries: Vec<crate::store::RangeEntry>,
    pub(super) lease_entries: Vec<crate::store::RangeEntry>,
    pub(super) stop_reason: Option<DriveStopReason>,
    pub(super) stop_now: bool,
}

impl QueueDiscovery {
    fn stopped() -> Self {
        Self {
            due_entries: Vec::new(),
            lease_entries: Vec::new(),
            stop_reason: Some(DriveStopReason::Capacity),
            stop_now: true,
        }
    }
}

pub(super) struct QueueDiscoveryContext<'a, S: JobStore, C: FnMut() -> MonotonicDeadline> {
    pub(super) system: &'a JobSystem<S>,
    pub(super) request: &'a DriveRequest,
    pub(super) clock: &'a mut C,
    pub(super) operation_budget: &'a mut OperationBudget,
    pub(super) budget: &'a mut DiscoveryBudget,
}

impl<S: JobStore, C: FnMut() -> MonotonicDeadline> QueueDiscoveryContext<'_, S, C> {
    pub(super) async fn discover(
        mut self,
        queue: Option<&QueueName>,
    ) -> JobResult<QueueDiscovery, S::Error> {
        let Some(due_scan) = self.scan_lane(KeyTag::Due, queue).await? else {
            return Ok(QueueDiscovery::stopped());
        };
        let mut result = QueueDiscovery {
            due_entries: due_scan.entries,
            lease_entries: Vec::new(),
            stop_reason: due_scan.stop_reason,
            stop_now: false,
        };
        let Some(lease_scan) = self.scan_lane(KeyTag::Lease, queue).await? else {
            result.stop_reason = Some(DriveStopReason::Capacity);
            result.stop_now = true;
            return Ok(result);
        };
        if result.stop_reason.is_none() {
            result.stop_reason = lease_scan.stop_reason;
        }
        result.lease_entries = lease_scan.entries;
        if self.budget.is_exhausted() {
            result.stop_reason = Some(DriveStopReason::Capacity);
            result.stop_now = true;
        }
        Ok(result)
    }

    async fn scan_lane(
        &mut self,
        tag: KeyTag,
        queue: Option<&QueueName>,
    ) -> JobResult<Option<DiscoveryScan>, S::Error> {
        let Some(page_limits) = self.budget.range_limits(
            self.system.store().capabilities(),
            self.request.max_claims(),
        ) else {
            return Ok(None);
        };
        if !self.operation_budget.reserve(1) {
            return Ok(None);
        }
        let first_page = read_index_page(self.system, tag, queue, None, page_limits).await?;
        collect_index_pages(
            IndexScanContext {
                system: self.system,
                request: self.request,
                clock: self.clock,
                operation_budget: self.operation_budget,
                budget: self.budget,
            },
            IndexScanDescriptor {
                tag,
                queue,
                first_page,
            },
        )
        .await
        .map(Some)
    }
}

struct DiscoveryScan {
    entries: Vec<crate::store::RangeEntry>,
    stop_reason: Option<DriveStopReason>,
}

impl DiscoveryScan {
    fn append_entries(
        &mut self,
        entries: Vec<crate::store::RangeEntry>,
        budget: &mut DiscoveryBudget,
    ) {
        for entry in entries {
            if !budget.reserve_entry(&entry) {
                self.stop_reason = Some(DriveStopReason::Capacity);
                return;
            }
            self.entries.push(entry);
        }
    }
}

struct IndexScanContext<'a, S: JobStore, C: FnMut() -> MonotonicDeadline> {
    system: &'a JobSystem<S>,
    request: &'a DriveRequest,
    clock: &'a mut C,
    operation_budget: &'a mut OperationBudget,
    budget: &'a mut DiscoveryBudget,
}

struct IndexScanDescriptor<'a> {
    tag: KeyTag,
    queue: Option<&'a QueueName>,
    first_page: RangePage,
}

impl<S: JobStore, C: FnMut() -> MonotonicDeadline> IndexScanContext<'_, S, C> {
    fn prepare_next_page(
        &mut self,
        scan: &mut DiscoveryScan,
        previous_continuation: &mut Option<StoreKey>,
        continuation: &StoreKey,
    ) -> Option<RangeLimits> {
        if previous_continuation.as_ref() == Some(continuation) {
            self.system
                .observe(crate::observer::JobEvent::CapacityLimited {
                    resource: crate::observer::CapacityResource::RangeProgress,
                });
            scan.stop_reason = Some(DriveStopReason::Capacity);
            return None;
        }
        if claim_deadline_reached(self.request, (self.clock)()) {
            scan.stop_reason = Some(DriveStopReason::Deadline);
            return None;
        }
        let Some(page_limits) = self.budget.range_limits(
            self.system.store().capabilities(),
            self.request.max_claims(),
        ) else {
            scan.stop_reason = Some(DriveStopReason::Capacity);
            return None;
        };
        if !self.operation_budget.reserve(1) {
            scan.stop_reason = Some(DriveStopReason::Capacity);
            return None;
        }
        *previous_continuation = Some(continuation.clone());
        Some(page_limits)
    }
}

async fn collect_index_pages<S: JobStore, C: FnMut() -> MonotonicDeadline>(
    mut context: IndexScanContext<'_, S, C>,
    descriptor: IndexScanDescriptor<'_>,
) -> JobResult<DiscoveryScan, S::Error> {
    let mut scan = DiscoveryScan {
        entries: Vec::with_capacity(
            (context.request.max_claims().get() as usize)
                .min(super::super::constants::MAX_DISCOVERY_ITEMS),
        ),
        stop_reason: None,
    };
    let mut page = descriptor.first_page;
    let mut previous_continuation = None;
    loop {
        let continuation = page.continuation.clone();
        scan.append_entries(page.entries, context.budget);
        if scan.stop_reason.is_some() {
            return Ok(scan);
        }
        let Some(continuation) = continuation else {
            break;
        };
        let Some(page_limits) =
            context.prepare_next_page(&mut scan, &mut previous_continuation, &continuation)
        else {
            break;
        };
        page = read_index_page(
            context.system,
            descriptor.tag,
            descriptor.queue,
            Some(continuation),
            page_limits,
        )
        .await?;
    }
    Ok(scan)
}

async fn read_index_page<S: JobStore>(
    system: &JobSystem<S>,
    tag: KeyTag,
    queue: Option<&QueueName>,
    continuation: Option<StoreKey>,
    limits: RangeLimits,
) -> JobResult<RangePage, S::Error> {
    let prefix = match tag {
        KeyTag::Due => queue.map_or_else(
            || keys::due_prefix(system.namespace()),
            |queue| keys::due_queue_prefix(system.namespace(), queue),
        )?,
        KeyTag::Lease => queue.map_or_else(
            || KeyCodec::encode(system.namespace(), KeyTag::Lease, &[]),
            |queue| keys::lease_queue_prefix(system.namespace(), queue),
        )?,
        _ => return Err(JobSystemError::PayloadCorrupt),
    };
    let end = KeyCodec::prefix_end(&prefix);
    let request = RangeRequestInput {
        start: Some(prefix),
        end,
        direction: RangeDirection::Forward,
        item_limit: limits.item_limit,
        byte_limit: limits.byte_limit,
        continuation,
    };
    system
        .store()
        .read_range(RangeRequest::try_from(request)?)
        .await
        .map_err(JobSystemError::Store)
}
