//! Versioned value envelopes and job-operation codecs.

mod constants;
mod envelope;
mod job;
mod operation;

#[cfg(test)]
mod envelope_tests;
#[cfg(test)]
mod operation_tests;

#[cfg(feature = "test-support")]
pub use envelope::DecodedValue;
pub use envelope::{ValueCodec, ValueTag};
pub(crate) use envelope::{decode_effect_mode, encode_effect_mode};
pub(crate) use job::job_definition_digest;
pub use job::{decode_job_record, encode_job_record};
pub(crate) use operation::{
    DecodedOperation, LiveOperationAuthority, decode_operation, encode_operation_marker,
    encode_operation_receipt, encode_operation_watermark,
};
