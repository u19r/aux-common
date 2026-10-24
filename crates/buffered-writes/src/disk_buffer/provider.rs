use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};

use futures_util::future::BoxFuture;

use super::journal::{DiskJournalInner, JournalEntry, sync_directory};
use crate::{
    buffer::{
        BufferAppendRequest, BufferAppendResult, BufferClaimRequest, BufferInspectRequest,
        BufferRenewRequest, BufferSealRequest, BufferSettleRequest, BufferSnapshot, ClaimedWork,
        LeasedSealedBatch, WriteBuffer,
    },
    configuration::{DurabilityClass, Namespace},
    constants::DEFAULT_BUFFER_MAX_BYTES,
    error::{BufferError, ConfigurationError},
    retention::RetentionState,
};
/// Versioned, checksummed append journal retention provider.
#[derive(Clone)]
pub struct DiskBuffer {
    namespace: Namespace,
    inner: Arc<Mutex<DiskJournalInner>>,
}

impl std::fmt::Debug for DiskBuffer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DiskBuffer")
    }
}

impl DiskBuffer {
    pub fn open(
        namespace: Namespace,
        directory: impl Into<PathBuf>,
    ) -> Result<Self, ConfigurationError> {
        Self::open_with_max_bytes(
            namespace,
            directory,
            (DEFAULT_BUFFER_MAX_BYTES as u64).saturating_mul(2),
        )
    }

    pub fn open_with_max_bytes(
        namespace: Namespace,
        directory: impl Into<PathBuf>,
        max_journal_bytes: u64,
    ) -> Result<Self, ConfigurationError> {
        let directory = directory.into();
        Self::validate_open_parameters(&directory, max_journal_bytes)?;
        let mut inner = DiskJournalInner::open(namespace.clone(), directory, max_journal_bytes)?;
        inner.recover_journal().map_err(|error| match error {
            BufferError::NamespaceMismatch => ConfigurationError::NamespaceMismatch,
            BufferError::UnsupportedVersion => ConfigurationError::InvalidDiskPath {
                reason: "unsupported disk journal version",
            },
            _ => ConfigurationError::InvalidDiskPath {
                reason: "failed to open or recover disk journal",
            },
        })?;
        sync_directory(&inner.directory).map_err(|_| ConfigurationError::InvalidDiskPath {
            reason: "failed to sync journal directory during recovery",
        })?;
        Ok(Self {
            namespace,
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    fn validate_open_parameters(
        directory: &std::path::Path,
        max_journal_bytes: u64,
    ) -> Result<(), ConfigurationError> {
        if directory.as_os_str().is_empty() {
            return Err(ConfigurationError::InvalidDiskPath {
                reason: "disk journal directory must not be empty",
            });
        }
        if max_journal_bytes < 10 {
            return Err(ConfigurationError::InvalidDiskPath {
                reason: "journal capacity must fit its header",
            });
        }
        Ok(())
    }

    pub fn compact_now(&self) -> Result<(), BufferError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| BufferError::StorageUnavailable {
                reason: "disk journal mutex poisoned",
            })?;
        let result = guard.compact();
        if matches!(result, Err(BufferError::StorageUnavailable { .. })) {
            guard.failed_commit = true;
        }
        result
    }

    #[must_use]
    pub fn has_interior_corruption(&self) -> bool {
        self.inner
            .lock()
            .is_ok_and(|guard| guard.interior_corruption)
    }

    fn run_blocking<F, R>(&self, op: F) -> BoxFuture<'static, Result<R, BufferError>>
    where
        F: FnOnce(&mut DiskJournalInner) -> Result<R, BufferError> + Send + 'static,
        R: Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let result = (|| {
                    let mut guard = inner.lock().map_err(|_| BufferError::StorageUnavailable {
                        reason: "disk journal mutex poisoned",
                    })?;
                    op(&mut guard)
                })();
                // End provider and OS-lock ownership before publishing
                // completion, including when the awaiting future was cancelled.
                drop(inner);
                result
            })
            .await
            .map_err(|_| BufferError::StorageUnavailable {
                reason: "disk journal blocking task failed",
            })?
        })
    }
}

impl DiskBuffer {
    fn update_state<R, F>(&self, operation: F) -> BoxFuture<'static, Result<R, BufferError>>
    where
        R: Send + 'static,
        F: FnOnce(&mut RetentionState) -> Result<R, BufferError> + Send + 'static,
    {
        self.run_blocking(move |inner| {
            if inner.interior_corruption || inner.failed_commit {
                return Err(BufferError::StorageUnavailable {
                    reason: "journal must be recovered before further mutations",
                });
            }
            let mut next = inner.state.clone();
            let result = operation(&mut next)?;
            let entry = JournalEntry::Snapshot {
                namespace: inner.namespace.clone(),
                state: Box::new(next),
            };
            if let Err(error) = inner.append_frame(1, &entry) {
                if !matches!(error, BufferError::Full) {
                    inner.failed_commit = true;
                }
                return Err(error);
            }
            let JournalEntry::Snapshot { state, .. } = entry;
            inner.state = *state;
            Ok(result)
        })
    }
}

impl WriteBuffer for DiskBuffer {
    fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    fn durability_class(&self) -> DurabilityClass {
        self.inner
            .lock()
            .map_or(DurabilityClass::DiskSynced, |state| state.durability())
    }
    fn append(
        &self,
        request: BufferAppendRequest,
    ) -> BoxFuture<'static, Result<BufferAppendResult, BufferError>> {
        let durability = self.durability_class();
        let identity = request.record.operation_id.clone();
        let future = self.update_state(move |state| state.append_record(request, durability));
        Box::pin(async move {
            match future.await {
                Err(BufferError::StorageUnavailable { .. } | BufferError::DeadlineExceeded) => {
                    Err(BufferError::AmbiguousAdmission {
                        operation_id: identity,
                    })
                }
                result => result,
            }
        })
    }
    fn claim(
        &self,
        request: BufferClaimRequest,
    ) -> BoxFuture<'static, Result<ClaimedWork, BufferError>> {
        self.update_state(move |state| Ok(state.claim_work(request)))
    }
    fn seal(
        &self,
        request: BufferSealRequest,
    ) -> BoxFuture<'static, Result<Option<LeasedSealedBatch>, BufferError>> {
        let namespace = self.namespace.clone();
        self.update_state(move |state| {
            state.seal_candidate(request, Some(Instant::now()), &namespace)
        })
    }
    fn renew(&self, request: BufferRenewRequest) -> BoxFuture<'static, Result<(), BufferError>> {
        self.update_state(move |state| state.renew_lease(request))
    }
    fn settle(&self, request: BufferSettleRequest) -> BoxFuture<'static, Result<(), BufferError>> {
        self.update_state(move |state| state.settle_batch(request))
    }
    fn inspect(
        &self,
        request: BufferInspectRequest,
    ) -> BoxFuture<'static, Result<BufferSnapshot, BufferError>> {
        self.run_blocking(move |inner| {
            if inner.failed_commit {
                return Err(BufferError::StorageUnavailable {
                    reason: "journal requires recovery",
                });
            }
            let durability = inner.durability();
            Ok(inner.state.inspect_state(request, durability))
        })
    }
}
