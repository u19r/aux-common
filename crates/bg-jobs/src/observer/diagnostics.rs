/// Binding resource observed at a scheduler capacity boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityResource {
    StoreOperations,
    DiscoveryItems,
    DiscoveryBytes,
    PayloadBytes,
    Fairness,
    RangeProgress,
}

impl CapacityResource {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::StoreOperations => "store_operations",
            Self::DiscoveryItems => "discovery_items",
            Self::DiscoveryBytes => "discovery_bytes",
            Self::PayloadBytes => "payload_bytes",
            Self::Fairness => "fairness",
            Self::RangeProgress => "range_progress",
        }
    }
}

/// Actual engine store calls, including enqueue, recovery, and lifecycle work.
/// Counts represent dispatched calls, including errors, not physical database
/// statements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreOperation {
    Get,
    GetMany,
    ReadRange,
    Commit,
}

impl StoreOperation {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::GetMany => "get_many",
            Self::ReadRange => "read_range",
            Self::Commit => "commit",
        }
    }
}
