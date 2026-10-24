use std::io::{self, Write};

use bytes::Bytes;
use serde::Serialize;

use crate::error::EncodeError;

/// JSON output whose logical length and requested allocation never exceed its
/// budget.
struct JsonOutput {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl JsonOutput {
    fn reserve_output(&mut self, required: usize) -> io::Result<()> {
        if required <= self.bytes.capacity() {
            return Ok(());
        }
        let target = self
            .bytes
            .capacity()
            .max(1)
            .saturating_mul(2)
            .max(required)
            .min(self.limit);
        self.bytes
            .try_reserve_exact(target.saturating_sub(self.bytes.len()))
            .map_err(|_| io::Error::other("JSON allocation failed"))
    }
}

impl Write for JsonOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("JSON byte budget exceeded"));
        }
        self.reserve_output(self.bytes.len().saturating_add(bytes.len()))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn encode_json<T: Serialize + ?Sized>(
    value: &T,
    limit: usize,
) -> Result<Bytes, EncodeError> {
    let mut output = JsonOutput {
        bytes: Vec::new(),
        limit,
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut output, value);
    if output.exceeded {
        return Err(EncodeError::PayloadTooLarge {
            size: limit.saturating_add(1),
            limit,
        });
    }
    result.map_err(|_| EncodeError::SerializationFailed)?;
    Ok(Bytes::from(output.bytes))
}
