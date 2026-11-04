use super::{ScheduleCursor, constants::CATALOG_CURSOR_BYTES};
use crate::{error::StoreDataError, time::Timestamp};

impl ScheduleCursor {
    /// The enclosing catalog owns the format version.
    pub(crate) fn encode_catalog_cursor(&self) -> [u8; CATALOG_CURSOR_BYTES] {
        let mut bytes = [0; CATALOG_CURSOR_BYTES];
        write_optional_timestamp(&mut bytes[0..9], self.next_due);
        write_optional_timestamp(&mut bytes[9..18], self.watermark);
        write_optional_timestamp(&mut bytes[18..27], self.last_intended);
        bytes[27..35].copy_from_slice(&self.revision.to_be_bytes());
        bytes[35..39].copy_from_slice(&self.generation.to_be_bytes());
        bytes[39] = u8::from(self.paused);
        bytes[40] = u8::from(self.enabled);
        bytes[41] = u8::from(self.active);
        bytes
    }

    pub(crate) fn decode_catalog_cursor(bytes: &[u8]) -> Result<Self, StoreDataError> {
        if bytes.len() != CATALOG_CURSOR_BYTES {
            return Err(StoreDataError::Malformed("schedule cursor length"));
        }
        Ok(Self {
            next_due: read_optional_timestamp(&bytes[0..9])?,
            watermark: read_optional_timestamp(&bytes[9..18])?,
            last_intended: read_optional_timestamp(&bytes[18..27])?,
            revision: u64::from_be_bytes(
                bytes[27..35]
                    .try_into()
                    .map_err(|_| StoreDataError::Truncated)?,
            ),
            generation: u32::from_be_bytes(
                bytes[35..39]
                    .try_into()
                    .map_err(|_| StoreDataError::Truncated)?,
            ),
            paused: read_bool(bytes[39])?,
            enabled: read_bool(bytes[40])?,
            active: read_bool(bytes[41])?,
        })
    }
}

fn write_optional_timestamp(bytes: &mut [u8], timestamp: Option<Timestamp>) {
    if let Some(timestamp) = timestamp {
        bytes[0] = 1;
        bytes[1..9].copy_from_slice(&timestamp.as_millis().to_be_bytes());
    }
}

fn read_optional_timestamp(bytes: &[u8]) -> Result<Option<Timestamp>, StoreDataError> {
    let value = i64::from_be_bytes(
        bytes[1..9]
            .try_into()
            .map_err(|_| StoreDataError::Truncated)?,
    );
    match (bytes[0], value) {
        (0, 0) => Ok(None),
        (1, value) => Ok(Some(Timestamp::from_millis(value))),
        _ => Err(StoreDataError::Malformed("schedule cursor timestamp")),
    }
}

fn read_bool(value: u8) -> Result<bool, StoreDataError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StoreDataError::Malformed("schedule cursor flag")),
    }
}
