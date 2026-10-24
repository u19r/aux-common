//! Internal durable key and marker construction.

mod constants;
mod keyspace;

pub(crate) use constants::MAX_DURABLE_PERMIT_SLOTS;
pub(crate) use keyspace::{
    cancellation_key, cancellation_value, dead_letter_key, dead_letter_value,
    decode_active_operation, decode_dedupe_value, decode_due_key, decode_operation_authority,
    decode_operation_fence_high_water, decode_timestamp_value, dedupe_key, dedupe_value, due_key,
    due_prefix, due_queue_prefix, due_value, fair_key, fair_state_key, fair_value, job_key,
    lease_key, lease_queue_prefix, lease_value, operation_key, operation_receipt_value,
    operation_value, operation_watermark_value, payload_key, permit_key_sets,
    permit_value_for_record, permit_value_matches_record, validate_empty_marker,
    validate_job_marker, wake_key, wake_value,
};
