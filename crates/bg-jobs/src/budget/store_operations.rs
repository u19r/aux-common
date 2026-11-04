//! Shared native-call admission budget for scheduling and commit recovery.

pub(crate) struct OperationBudget {
    pub(crate) remaining: u32,
    observer: std::sync::Arc<dyn crate::observer::JobObserver>,
}

impl OperationBudget {
    pub(crate) fn new(
        limit: u32,
        observer: std::sync::Arc<dyn crate::observer::JobObserver>,
    ) -> Self {
        Self {
            remaining: limit,
            observer,
        }
    }

    pub(crate) fn reserve(&mut self, operations: u32) -> bool {
        if operations > self.remaining {
            self.observer
                .observe(crate::observer::JobEvent::CapacityLimited {
                    resource: crate::observer::CapacityResource::StoreOperations,
                });
            return false;
        }
        self.observer
            .observe(crate::observer::JobEvent::StoreOperationsReserved { operations });
        self.remaining -= operations;
        true
    }
}
