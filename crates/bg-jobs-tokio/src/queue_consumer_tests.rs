use std::{
    num::{NonZeroU32, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::sync::{Notify, Semaphore, watch};

use crate::{QueueConsumer, QueueOutcome, QueueWorker};

struct Worker {
    received: AtomicUsize,
    started: AtomicUsize,
    settled: AtomicUsize,
    renewed: AtomicUsize,
    limit: usize,
    gate: Semaphore,
    changed: Notify,
    renewal_succeeds: bool,
    receive_failure: bool,
}

impl Worker {
    fn new(limit: usize) -> Self {
        Self {
            received: AtomicUsize::new(0),
            started: AtomicUsize::new(0),
            settled: AtomicUsize::new(0),
            renewed: AtomicUsize::new(0),
            limit,
            gate: Semaphore::new(0),
            changed: Notify::new(),
            renewal_succeeds: true,
            receive_failure: false,
        }
    }

    async fn wait_for(&self, counter: &AtomicUsize, count: usize) {
        loop {
            let changed = self.changed.notified();
            if counter.load(Ordering::SeqCst) >= count {
                return;
            }
            changed.await;
        }
    }
}

impl QueueWorker for Worker {
    type Message = usize;

    async fn receive(&self) -> Result<Option<usize>, Duration> {
        let number = self.received.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_waiters();
        if self.receive_failure {
            return Err(Duration::from_secs(30));
        }
        if number >= self.limit {
            std::future::pending::<()>().await;
        }
        Ok(Some(number))
    }

    async fn execute(&self, _: &usize) -> Option<QueueOutcome> {
        self.started.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_waiters();
        self.gate.acquire().await.unwrap().forget();
        Some(QueueOutcome::RetryAfter(Duration::from_secs(7)))
    }

    async fn renew(&self, _: &usize) -> bool {
        self.renewed.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_waiters();
        self.renewal_succeeds
    }

    async fn settle(&self, _: &usize, outcome: QueueOutcome) {
        assert_eq!(outcome, QueueOutcome::RetryAfter(Duration::from_secs(7)));
        self.settled.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_waiters();
    }
}

#[tokio::test]
async fn given_more_deliveries_than_workers_when_shutdown_begins_then_only_in_flight_handlers_finish()
 {
    let worker = Arc::new(Worker::new(100));
    let (shutdown, receiver) = watch::channel(false);
    let consumer = QueueConsumer::new(
        worker.clone(),
        NonZeroUsize::new(2).unwrap(),
        NonZeroU32::MIN,
    );
    let running = tokio::spawn(consumer.run_until_shutdown(receiver));
    worker.wait_for(&worker.started, 2).await;
    assert_eq!(worker.received.load(Ordering::SeqCst), 2);
    shutdown.send(true).unwrap();
    worker.gate.add_permits(2);
    running.await.unwrap().unwrap();
    assert_eq!(worker.started.load(Ordering::SeqCst), 2);
    assert_eq!(worker.settled.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn given_a_lost_visibility_lease_when_renewal_fails_then_execution_is_dropped_without_settlement()
 {
    let worker = Arc::new(Worker {
        renewal_succeeds: false,
        ..Worker::new(1)
    });
    let (shutdown, receiver) = watch::channel(false);
    let consumer = QueueConsumer::new(worker.clone(), NonZeroUsize::MIN, NonZeroU32::MIN);
    let running = tokio::spawn(consumer.run_until_shutdown(receiver));
    worker.wait_for(&worker.started, 1).await;
    tokio::time::advance(Duration::from_secs(1)).await;
    worker.wait_for(&worker.renewed, 1).await;
    shutdown.send(true).unwrap();
    running.await.unwrap().unwrap();
    assert_eq!(worker.settled.load(Ordering::SeqCst), 0);
    assert_eq!(worker.gate.available_permits(), 0);
}

#[tokio::test(start_paused = true)]
async fn given_a_shutdown_during_execution_when_the_lease_needs_renewal_then_the_handler_drains_with_renewal()
 {
    let worker = Arc::new(Worker::new(1));
    let (shutdown, receiver) = watch::channel(false);
    let consumer = QueueConsumer::new(worker.clone(), NonZeroUsize::MIN, NonZeroU32::MIN);
    let running = tokio::spawn(consumer.run_until_shutdown(receiver));
    worker.wait_for(&worker.started, 1).await;
    shutdown.send(true).unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    worker.wait_for(&worker.renewed, 1).await;
    worker.gate.add_permits(1);
    running.await.unwrap().unwrap();
    assert_eq!(worker.settled.load(Ordering::SeqCst), 1);
    assert_eq!(worker.received.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn given_a_receive_failure_when_shutdown_occurs_during_backoff_then_no_second_receive_runs() {
    let worker = Arc::new(Worker {
        receive_failure: true,
        ..Worker::new(0)
    });
    let (shutdown, receiver) = watch::channel(false);
    let consumer = QueueConsumer::new(worker.clone(), NonZeroUsize::MIN, NonZeroU32::MIN);
    let running = tokio::spawn(consumer.run_until_shutdown(receiver));
    worker.wait_for(&worker.received, 1).await;
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(worker.received.load(Ordering::SeqCst), 1);
    shutdown.send(true).unwrap();
    running.await.unwrap().unwrap();
    assert_eq!(worker.received.load(Ordering::SeqCst), 1);
    assert_eq!(worker.started.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn given_an_aborted_consumer_when_execution_is_pending_then_no_detached_worker_remains() {
    let worker = Arc::new(Worker::new(1));
    let (_shutdown, receiver) = watch::channel(false);
    let consumer = QueueConsumer::new(worker.clone(), NonZeroUsize::MIN, NonZeroU32::MIN);
    let running = tokio::spawn(consumer.run_until_shutdown(receiver));
    worker.wait_for(&worker.started, 1).await;
    running.abort();
    assert!(running.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(1), async {
        while Arc::strong_count(&worker) > 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("owned queue workers are aborted");
    assert_eq!(worker.settled.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn given_a_closed_shutdown_channel_when_the_consumer_starts_then_no_receive_or_execution_runs()
 {
    let worker = Arc::new(Worker::new(1));
    let (shutdown, receiver) = watch::channel(false);
    drop(shutdown);
    QueueConsumer::new(worker.clone(), NonZeroUsize::MIN, NonZeroU32::MIN)
        .run_until_shutdown(receiver)
        .await
        .unwrap();
    assert_eq!(worker.received.load(Ordering::SeqCst), 0);
    assert_eq!(worker.started.load(Ordering::SeqCst), 0);
}
