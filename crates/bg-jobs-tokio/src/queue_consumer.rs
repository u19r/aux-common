use std::{
    num::{NonZeroU32, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

use tokio::{
    sync::watch,
    task::{JoinError, JoinSet},
};

use crate::{LeaseHeartbeat, QueueOutcome, QueueWorker, constants::MINIMUM_QUEUE_RECEIVE_RETRY};

/// Bounded consumption of an existing leased queue. Queue adapters own I/O;
/// durable job lifecycle and effect authority remain with `bg-jobs`.
///
/// Shutdown stops receives and new executions, drains in-flight handlers, and
/// renews their visibility until settlement. Dropping this future aborts its
/// owned workers; transport leases retain unfinished deliveries.
pub struct QueueConsumer<W> {
    worker: Arc<W>,
    concurrency: NonZeroUsize,
    heartbeat: Duration,
}

impl<W: QueueWorker> QueueConsumer<W> {
    pub fn new(worker: Arc<W>, concurrency: NonZeroUsize, heartbeat_seconds: NonZeroU32) -> Self {
        Self {
            worker,
            concurrency,
            heartbeat: Duration::from_secs(u64::from(heartbeat_seconds.get())),
        }
    }

    pub async fn run_until_shutdown(
        self,
        shutdown: watch::Receiver<bool>,
    ) -> Result<(), JoinError> {
        let mut workers = JoinSet::new();
        for _ in 0..self.concurrency.get() {
            workers.spawn(run_worker(
                Arc::clone(&self.worker),
                self.heartbeat,
                shutdown.clone(),
            ));
        }
        while let Some(result) = workers.join_next().await {
            result?;
        }
        Ok(())
    }
}

async fn run_worker<W: QueueWorker>(
    worker: Arc<W>,
    heartbeat: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        if is_shutdown_requested(&shutdown) {
            return;
        }
        let received = tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => return,
            received = worker.receive() => received,
        };
        let message = match received {
            Ok(Some(message)) => message,
            Ok(None) => continue,
            Err(delay) => {
                tokio::select! {
                    _ = wait_for_shutdown(&mut shutdown) => return,
                    _ = tokio::time::sleep(delay.max(MINIMUM_QUEUE_RECEIVE_RETRY)) => {}
                }
                continue;
            }
        };
        if is_shutdown_requested(&shutdown) {
            return;
        }
        if let Some(outcome) = execute_delivery(worker.as_ref(), &message, heartbeat).await {
            worker.settle(&message, outcome).await;
        }
    }
}

async fn execute_delivery<W: QueueWorker>(
    worker: &W,
    message: &W::Message,
    heartbeat: Duration,
) -> Option<QueueOutcome> {
    LeaseHeartbeat::CancelOnLoss(heartbeat)
        .run(worker.execute(message), || async {
            if worker.renew(message).await {
                Ok(())
            } else {
                Err(())
            }
        })
        .await
        .ok()
        .flatten()
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() || shutdown.changed().await.is_err() {
            return;
        }
    }
}

fn is_shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow() || shutdown.has_changed().is_err()
}
