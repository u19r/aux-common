//! Bounds and codec tags for the store-protocol connector.

pub(super) const MAX_INLINE_PAYLOAD_BYTES: i64 = bg_jobs::MAX_INLINE_PAYLOAD_BYTES as i64;
pub(super) const MAX_MANIFEST_BYTES: i64 = 4_096;
pub(super) const MAX_CHUNK_BYTES: i64 = 65_536;
pub(super) const MAX_DIGEST_BYTES: i64 = 64;
pub(super) const MAX_CHECKPOINT_BYTES: i64 = 65_536;
pub(super) const MAX_COMPLETION_RECEIPTS: i64 = 2;
pub(super) const ALL_COMMAND_FAMILIES: [&str; 15] = [
    "StoreEnqueue",
    "StoreSelectClaim",
    "StoreClaim",
    "StoreRenew",
    "StoreComplete",
    "StoreDeadLetter",
    "StoreRedrive",
    "StoreUnknown",
    "StoreReconcile",
    "StoreCorrupt",
    "StoreDropRoute",
    "StoreRepair",
    "StorePurge",
    "StoreAdvance",
    "StoreExpire",
];

pub(super) const OPERATION_VERSION: u8 = 4;
pub(super) const ROUTE_VERSION: u8 = 4;
pub(super) const FAULT_VERSION: u8 = 1;
pub(super) const ROUTE_COMPONENT: &[u8] = b"connector-routes";
pub(super) const FAULT_COMPONENT: &[u8] = b"connector-fault";
pub(super) const UNKNOWN_COMPONENT: &[u8] = b"connector-unknown";
pub(super) const CLAIM_COMPONENT: &[u8] = b"connector-claim";
