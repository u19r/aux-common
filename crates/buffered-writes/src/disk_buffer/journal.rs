use std::{
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::journal_frame::{checksum, frame_checksum};
use crate::{
    configuration::DurabilityClass,
    constants::{
        DISK_FRAME_HEADER_BYTES, DISK_JOURNAL_COMPACT_FILE_NAME, DISK_JOURNAL_MAGIC,
        DISK_JOURNAL_VERSION, MAX_DISK_FRAME_BYTES,
    },
    error::BufferError,
    retention::RetentionState,
};

#[derive(Clone, Serialize, Deserialize)]
pub(super) enum JournalEntry {
    Snapshot {
        namespace: crate::Namespace,
        state: Box<crate::retention::RetentionState>,
    },
}

impl JournalEntry {
    pub(super) fn decode_state(
        payload: &[u8],
        expected: &crate::Namespace,
    ) -> Result<Box<RetentionState>, BufferError> {
        let Self::Snapshot { namespace, state } =
            serde_json::from_slice(payload).map_err(|_| BufferError::CorruptStorage {
                reason: "invalid persisted journal snapshot",
            })?;
        if &namespace != expected {
            return Err(BufferError::NamespaceMismatch);
        }
        state.validate_recovery(expected)?;
        Ok(state)
    }
}

pub(super) struct DiskJournalInner {
    pub(super) namespace: crate::Namespace,
    pub(super) directory: PathBuf,
    pub(super) writer_lock: File,
    pub(super) journal_path: PathBuf,
    pub(super) max_journal_bytes: u64,
    pub(super) state: RetentionState,
    pub(super) interior_corruption: bool,
    pub(super) failed_commit: bool,
}

impl Drop for DiskJournalInner {
    fn drop(&mut self) {
        // Closing one descriptor can leave an inherited/duplicated descriptor
        // holding its lock. End authority when the final provider owner drops.
        let _ = self.writer_lock.unlock();
    }
}

impl DiskJournalInner {
    pub(super) fn durability(&self) -> DurabilityClass {
        DurabilityClass::DiskSynced
    }

    pub(super) fn append_frame(
        &mut self,
        frame_kind: u8,
        entry: &JournalEntry,
    ) -> Result<(), BufferError> {
        let payload = serde_json::to_vec(entry).map_err(|_| BufferError::CorruptStorage {
            reason: "failed to serialize journal entry",
        })?;
        let mut file = self.prepare_append(payload.len())?;
        file.seek(SeekFrom::End(0))
            .map_err(|_| BufferError::StorageUnavailable {
                reason: "failed to seek journal end",
            })?;
        #[cfg(test)]
        super::journal_tests::crash_boundary("append-before-frame");
        write_frame(&mut file, frame_kind, &payload)?;
        #[cfg(test)]
        super::journal_tests::pause_before_sync(&self.directory);
        file.sync_all()
            .map_err(|_| BufferError::StorageUnavailable {
                reason: "failed to sync journal file",
            })?;
        #[cfg(test)]
        super::journal_tests::crash_boundary("append-after-sync");
        Ok(())
    }

    fn prepare_append(&mut self, payload_len: usize) -> Result<File, BufferError> {
        let frame_len = (DISK_FRAME_HEADER_BYTES + payload_len) as u64;
        self.validate_snapshot_size(payload_len)?;
        let mut file = self.ensure_journal_initialized()?;
        if file
            .metadata()
            .map_err(|_| BufferError::StorageUnavailable {
                reason: "failed to stat journal file",
            })?
            .len()
            .saturating_add(frame_len)
            > self.max_journal_bytes
        {
            self.compact()?;
            file = self.ensure_journal_initialized()?;
        }
        if file
            .metadata()
            .map_err(|_| BufferError::StorageUnavailable {
                reason: "failed to inspect journal capacity",
            })?
            .len()
            .saturating_add(frame_len)
            > self.max_journal_bytes
        {
            return Err(BufferError::Full);
        }
        Ok(file)
    }

    fn validate_snapshot_size(&self, payload_len: usize) -> Result<(), BufferError> {
        if payload_len > MAX_DISK_FRAME_BYTES
            || (DISK_FRAME_HEADER_BYTES as u64)
                .saturating_add(payload_len as u64)
                .saturating_add(10)
                > self.max_journal_bytes
        {
            return Err(BufferError::Full);
        }
        Ok(())
    }

    pub(super) fn compact(&mut self) -> Result<(), BufferError> {
        if self.interior_corruption || self.failed_commit {
            return Err(BufferError::StorageUnavailable {
                reason: "journal must be recovered before compaction",
            });
        }
        let entry = JournalEntry::Snapshot {
            namespace: self.namespace.clone(),
            state: Box::new(self.state.clone()),
        };
        let payload = serde_json::to_vec(&entry).map_err(|_| BufferError::CorruptStorage {
            reason: "failed to encode retained-state checkpoint",
        })?;
        self.validate_snapshot_size(payload.len())?;
        self.replace_checkpoint(&payload)?;
        Ok(())
    }

    fn replace_checkpoint(&self, payload: &[u8]) -> Result<(), BufferError> {
        let compact_path = self.directory.join(DISK_JOURNAL_COMPACT_FILE_NAME);
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&compact_path)
            .map_err(|_| BufferError::StorageUnavailable {
                reason: "failed to create compact journal file",
            })?;
        write_journal_header(&mut file)?;
        #[cfg(test)]
        super::journal_tests::crash_boundary("compact-after-header");
        write_frame(&mut file, 1, payload)?;
        file.sync_all()
            .map_err(|_| BufferError::StorageUnavailable {
                reason: "failed to sync compact journal file",
            })?;
        #[cfg(test)]
        super::journal_tests::crash_boundary("compact-after-sync");
        drop(file);
        fs::rename(&compact_path, &self.journal_path).map_err(|_| {
            BufferError::StorageUnavailable {
                reason: "failed to atomically replace journal file",
            }
        })?;
        #[cfg(test)]
        super::journal_tests::crash_boundary("compact-after-replace");
        sync_directory(&self.directory)?;
        #[cfg(test)]
        super::journal_tests::crash_boundary("compact-after-directory-sync");
        Ok(())
    }
}
pub(super) fn write_journal_header(file: &mut File) -> Result<(), BufferError> {
    let mut header = [0u8; 10];
    header[..8].copy_from_slice(DISK_JOURNAL_MAGIC);
    header[8..10].copy_from_slice(&DISK_JOURNAL_VERSION.to_le_bytes());
    file.write_all(&header)
        .map_err(|_| BufferError::StorageUnavailable {
            reason: "failed to write journal header",
        })
}

pub(super) fn write_frame(
    file: &mut File,
    frame_kind: u8,
    payload: &[u8],
) -> Result<(), BufferError> {
    let len = u32::try_from(payload.len()).map_err(|_| BufferError::OversizedItem {
        size: payload.len(),
        limit: MAX_DISK_FRAME_BYTES,
    })?;
    let crc = frame_checksum(frame_kind, payload);
    let mut header = [0u8; DISK_FRAME_HEADER_BYTES];
    header[0] = frame_kind;
    header[1..5].copy_from_slice(&len.to_le_bytes());
    header[5..9].copy_from_slice(&crc);
    let header_checksum = checksum(&header[..9]);
    header[9..13].copy_from_slice(&header_checksum);
    file.write_all(&header)
        .map_err(|_| BufferError::StorageUnavailable {
            reason: "failed to write journal frame header",
        })?;
    #[cfg(test)]
    super::journal_tests::crash_boundary("frame-after-header");
    file.write_all(payload)
        .map_err(|_| BufferError::StorageUnavailable {
            reason: "failed to write journal frame payload",
        })?;
    #[cfg(test)]
    super::journal_tests::crash_boundary("frame-after-payload");
    Ok(())
}

pub(super) fn truncate_file_at(path: &Path, len: u64) -> Result<(), BufferError> {
    let file =
        OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|_| BufferError::StorageUnavailable {
                reason: "failed to open journal for tail truncation",
            })?;
    file.set_len(len)
        .and_then(|()| file.sync_all())
        .map_err(|_| BufferError::StorageUnavailable {
            reason: "failed to truncate incomplete trailing journal frame",
        })
}

pub(super) fn sync_directory(dir: &Path) -> Result<(), BufferError> {
    File::open(dir)
        .and_then(|file| file.sync_all())
        .map_err(|_| BufferError::StorageUnavailable {
            reason: "failed to sync journal directory",
        })
}
