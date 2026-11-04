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

// Keep the connector's finite caller-result exposure aligned with the Quint
// model. Completion details have no persisted representation.
pub(super) const MAX_COMPLETION_RECEIPTS: usize = 2;
pub(super) const MAX_UNRELATED_PROGRESS: i64 = 4;
