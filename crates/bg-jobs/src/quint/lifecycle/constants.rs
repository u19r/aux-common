pub(super) const ALL_COMMAND_FAMILIES: [&str; 16] = [
    "LifecycleEnqueue",
    "LifecycleSelectClaim",
    "LifecycleClaim",
    "LifecycleRenew",
    "LifecycleCheckpoint",
    "LifecycleHandle",
    "LifecycleComplete",
    "LifecycleExpose",
    "LifecycleCancel",
    "LifecycleAdvance",
    "LifecycleExpire",
    "LifecycleUnknown",
    "LifecycleReconcile",
    "LifecycleCorrupt",
    "LifecycleRepair",
    "LifecycleRedrive",
];

// Keep the connector's finite exposure bookkeeping aligned with the Quint
// model. Terminal receipts themselves remain public store observations; this
// set only records which of those receipts the model has exposed as
// completion details, a value with no persisted representation.
pub(super) const MAX_COMPLETION_RECEIPTS: usize = 2;
pub(super) const MAX_UNRELATED_PROGRESS: i64 = 4;
