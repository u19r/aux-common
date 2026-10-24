use std::io::{self, Write};

use serde::Serialize;

use super::JsError;

pub(crate) struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}
impl BoundedWriter {
    pub(crate) fn serialize(
        value: &impl Serialize,
        limit: usize,
        overflow: JsError,
    ) -> Result<Vec<u8>, JsError> {
        let mut writer = Self {
            bytes: Vec::new(),
            limit,
            overflowed: false,
        };
        if serde_json::to_writer(&mut writer, value).is_err() {
            return Err(if writer.overflowed {
                overflow
            } else {
                JsError::InvalidInvocation
            });
        }
        Ok(writer.bytes)
    }
}
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.overflowed = true;
            return Err(io::Error::other("serialization_limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
