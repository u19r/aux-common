//! Wire constants shared by value codecs.

pub(super) const VALUE_VERSION: u8 = 0x01;
pub(super) const VALUE_HEADER_BYTES: usize = 6;
pub(super) const MAX_VALUE_BODY_BYTES: usize = 1_048_576;

pub(super) const JOB_DEFINITION_CAPACITY: usize = 256;
pub(super) const JOB_DEFINITION_VERSION: u8 = 1;
