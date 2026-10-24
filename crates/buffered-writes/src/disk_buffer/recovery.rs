use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};

use super::{
    journal::{
        DiskJournalInner, JournalEntry, sync_directory, truncate_file_at, write_journal_header,
    },
    journal_frame::JournalFrame,
};
use crate::{
    Namespace,
    constants::{
        DISK_JOURNAL_FILE_NAME, DISK_JOURNAL_LOCK_FILE_NAME, DISK_JOURNAL_MAGIC,
        DISK_JOURNAL_VERSION,
    },
    error::{BufferError, ConfigurationError},
    retention::RetentionState,
};
impl DiskJournalInner {
    pub(super) fn open(
        namespace: Namespace,
        directory: PathBuf,
        max_journal_bytes: u64,
    ) -> Result<Self, ConfigurationError> {
        Self::create_durable_directory(&directory)?;
        let writer_lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join(DISK_JOURNAL_LOCK_FILE_NAME))
            .map_err(|_| ConfigurationError::InvalidDiskPath {
                reason: "failed to open writer lock file",
            })?;
        writer_lock
            .try_lock()
            .map_err(|_| ConfigurationError::InvalidDiskPath {
                reason: "disk journal already has an active writer",
            })?;
        Ok(Self {
            namespace,
            journal_path: directory.join(DISK_JOURNAL_FILE_NAME),
            directory,
            writer_lock,
            max_journal_bytes,
            state: RetentionState::default(),
            interior_corruption: false,
            failed_commit: false,
        })
    }

    fn create_durable_directory(directory: &Path) -> Result<(), ConfigurationError> {
        let mut missing = Vec::new();
        let mut current = directory;
        while !current.as_os_str().is_empty() && !current.exists() {
            missing.push(current);
            let Some(parent) = current.parent() else {
                break;
            };
            current = parent;
        }
        fs::create_dir_all(directory).map_err(|_| ConfigurationError::InvalidDiskPath {
            reason: "failed to create disk journal directory",
        })?;
        for path in missing.into_iter().rev() {
            let parent = path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            sync_directory(parent).map_err(|_| ConfigurationError::InvalidDiskPath {
                reason: "failed to sync new journal directory ancestry",
            })?;
        }
        Ok(())
    }

    pub(super) fn ensure_journal_initialized(&self) -> Result<File, BufferError> {
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&self.journal_path)
            .map_err(|_| BufferError::StorageUnavailable {
                reason: "failed to open journal file",
            })?;
        let len = file
            .metadata()
            .map_err(|_| BufferError::StorageUnavailable {
                reason: "failed to read journal metadata",
            })?
            .len();
        if len == 0 {
            write_journal_header(&mut file)?;
            file.sync_all()
                .map_err(|_| BufferError::StorageUnavailable {
                    reason: "failed to sync journal header",
                })?;
            sync_directory(&self.directory)?;
        }
        Ok(file)
    }

    pub(super) fn recover_journal(&mut self) -> Result<(), BufferError> {
        if !self.journal_path.exists() {
            let _ = self.ensure_journal_initialized()?;
            return Ok(());
        }
        let bytes = self.read_bounded_journal()?;
        if bytes.is_empty() {
            let _ = self.ensure_journal_initialized()?;
            return Ok(());
        }
        if bytes.len() < 10 || &bytes[..8] != DISK_JOURNAL_MAGIC {
            return Err(BufferError::CorruptStorage {
                reason: "invalid journal magic header",
            });
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != DISK_JOURNAL_VERSION {
            return Err(BufferError::UnsupportedVersion);
        }
        self.restore_frames(&bytes)
    }

    fn read_bounded_journal(&self) -> Result<Vec<u8>, BufferError> {
        let file = File::open(&self.journal_path).map_err(|_| BufferError::StorageUnavailable {
            reason: "failed to open journal for recovery",
        })?;
        let length = file
            .metadata()
            .map_err(|_| BufferError::StorageUnavailable {
                reason: "failed to stat journal for recovery",
            })?
            .len();
        if length > self.max_journal_bytes {
            return Err(BufferError::Full);
        }
        let mut bytes = Vec::new();
        file.take(self.max_journal_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| BufferError::StorageUnavailable {
                reason: "failed to read journal file",
            })?;
        if bytes.len() as u64 > self.max_journal_bytes {
            return Err(BufferError::Full);
        }
        Ok(bytes)
    }

    fn restore_frames(&mut self, bytes: &[u8]) -> Result<(), BufferError> {
        let mut offset = 10;
        while offset < bytes.len() {
            let tail = &bytes[offset..];
            match JournalFrame::from(tail) {
                JournalFrame::Complete { payload, bytes } => {
                    if !self.restore_checkpoint(payload)? {
                        break;
                    }
                    offset += bytes;
                }
                JournalFrame::Incomplete => {
                    truncate_file_at(&self.journal_path, offset as u64)?;
                    break;
                }
                JournalFrame::Corrupt => {
                    self.mark_corrupt_journal();
                    break;
                }
            }
        }
        Ok(())
    }

    fn restore_checkpoint(&mut self, payload: &[u8]) -> Result<bool, BufferError> {
        match JournalEntry::decode_state(payload, &self.namespace) {
            Ok(state) => {
                self.state = *state;
                Ok(true)
            }
            Err(error @ BufferError::NamespaceMismatch) => Err(error),
            Err(_) => {
                self.mark_corrupt_journal();
                Ok(false)
            }
        }
    }

    fn mark_corrupt_journal(&mut self) {
        // The canonical journal is the quarantine artifact. Leave its exact
        // bytes intact and block mutation; copying its tail on every restart is
        // unbounded.
        self.interior_corruption = true;
        self.state.quarantined_records = self.state.quarantined_records.saturating_add(1);
    }
}
