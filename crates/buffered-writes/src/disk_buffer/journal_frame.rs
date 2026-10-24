use sha2::{Digest as _, Sha256};

use crate::constants::{DISK_FRAME_HEADER_BYTES, MAX_DISK_FRAME_BYTES};

pub(super) enum JournalFrame<'a> {
    Complete { payload: &'a [u8], bytes: usize },
    Incomplete,
    Corrupt,
}
impl<'a> From<&'a [u8]> for JournalFrame<'a> {
    fn from(tail: &'a [u8]) -> Self {
        if tail.len() < DISK_FRAME_HEADER_BYTES {
            return Self::Incomplete;
        }
        if tail[0] != 1 || checksum(&tail[..9]) != tail[9..13] {
            return Self::Corrupt;
        }
        let length = u32::from_le_bytes([tail[1], tail[2], tail[3], tail[4]]) as usize;
        if length > MAX_DISK_FRAME_BYTES {
            return Self::Corrupt;
        }
        let end = DISK_FRAME_HEADER_BYTES + length;
        if end > tail.len() {
            return Self::Incomplete;
        }
        let payload = &tail[DISK_FRAME_HEADER_BYTES..end];
        if frame_checksum(tail[0], payload) != tail[5..9] {
            return Self::Corrupt;
        }
        Self::Complete {
            payload,
            bytes: end,
        }
    }
}

pub(super) fn frame_checksum(kind: u8, payload: &[u8]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update([kind]);
    hasher.update((payload.len() as u32).to_le_bytes());
    hasher.update(payload);
    let digest = hasher.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}
pub(super) fn checksum(bytes: &[u8]) -> [u8; 4] {
    let digest = Sha256::digest(bytes);
    [digest[0], digest[1], digest[2], digest[3]]
}
