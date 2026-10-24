//! Job-record encoding and decoding.

mod encoder;
mod reader;

#[cfg(test)]
mod encoder_tests;
#[cfg(test)]
mod reader_tests;

pub use encoder::encode_job_record;
pub(crate) use encoder::job_definition_digest;
pub use reader::decode_job_record;
