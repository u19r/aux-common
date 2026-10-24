use std::{
    future::Future,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::{
    runtime::Handle,
    sync::{Semaphore, mpsc},
    task::JoinHandle,
};

use crate::{
    LoadUnavailable,
    constants::{
        DEFAULT_REFRESH_BYTES, MAX_LOAD_KEYS, REFRESH_EXECUTOR_WORKERS, REFRESH_JOB_OVERHEAD_BYTES,
        REFRESH_KEY_COPY_CHARGE,
    },
    refresh_cancellation::RefreshCancellation,
    refresh_job::RefreshJob,
};

/// Bounded refresh-future execution. CacheCore retains generation/publication
/// ownership; storage sources separately own physical batching and cold
/// priority. Admission covers queued and active futures through source-future
/// destruction.
pub struct RefreshExecutor {
    sender: mpsc::Sender<RefreshJob>,
    receiver: Mutex<Option<mpsc::Receiver<RefreshJob>>>,
    slots: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
    workers: OnceLock<Vec<JoinHandle<()>>>,
    rejected: AtomicU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefreshExecutorStats {
    pub jobs: usize,
    pub charged_bytes: usize,
    pub workers: usize,
    pub rejected: u64,
}

impl Default for RefreshExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl RefreshExecutor {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(MAX_LOAD_KEYS);
        Self {
            sender,
            receiver: Mutex::new(Some(receiver)),
            slots: Arc::new(Semaphore::new(MAX_LOAD_KEYS)),
            bytes: Arc::new(Semaphore::new(DEFAULT_REFRESH_BYTES)),
            workers: OnceLock::new(),
            rejected: AtomicU64::new(0),
        }
    }

    pub fn stats(&self) -> RefreshExecutorStats {
        RefreshExecutorStats {
            jobs: MAX_LOAD_KEYS - self.slots.available_permits(),
            charged_bytes: DEFAULT_REFRESH_BYTES - self.bytes.available_permits(),
            workers: self.workers.get().map_or(0, Vec::len),
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn try_submit<F: Future<Output = ()> + Send + 'static>(
        &self,
        runtime: &Handle,
        key_bytes: usize,
        build: impl FnOnce() -> F,
    ) -> Result<RefreshCancellation, LoadUnavailable> {
        let bytes = key_bytes
            .checked_mul(REFRESH_KEY_COPY_CHARGE)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<F>()))
            .and_then(|bytes| bytes.checked_add(REFRESH_JOB_OVERHEAD_BYTES))
            .and_then(|bytes| u32::try_from(bytes).ok())
            .ok_or_else(|| self.reject_submission())?;
        let slots = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| self.reject_submission())?;
        let bytes = Arc::clone(&self.bytes)
            .try_acquire_many_owned(bytes)
            .map_err(|_| self.reject_submission())?;
        self.workers.get_or_init(|| self.start_workers(runtime));
        let (job, cancellation) = RefreshJob::new(build(), slots, bytes);
        self.sender
            .try_send(job)
            .map_err(|_| self.reject_submission())?;
        Ok(cancellation)
    }

    fn reject_submission(&self) -> LoadUnavailable {
        self.rejected.fetch_add(1, Ordering::Relaxed);
        LoadUnavailable::Full
    }

    fn start_workers(&self, runtime: &Handle) -> Vec<JoinHandle<()>> {
        let receiver = self
            .receiver
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        let Some(receiver) = receiver else {
            return Vec::new();
        };
        // Only workers own the receiver. Runtime shutdown drains queued
        // futures, including any database/cache references, even if senders
        // remain alive.
        let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
        (0..REFRESH_EXECUTOR_WORKERS)
            .map(|_| {
                let receiver = Arc::clone(&receiver);
                runtime.spawn(async move {
                    loop {
                        let job = receiver.lock().await.recv().await;
                        let Some(job) = job else {
                            break;
                        };
                        job.execute().await;
                    }
                })
            })
            .collect()
    }
}

impl Drop for RefreshExecutor {
    fn drop(&mut self) {
        if let Some(workers) = self.workers.get() {
            for worker in workers {
                worker.abort();
            }
        }
    }
}
