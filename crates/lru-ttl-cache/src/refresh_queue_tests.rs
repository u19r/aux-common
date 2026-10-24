use std::{
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use crate::{
    RefreshAdmission as Admission, RefreshBudget, RefreshDemand as Demand, RefreshQueue,
    RefreshQueueLimits, RefreshTicket, RefreshWork,
};

fn budget(keys: usize, bytes: usize) -> RefreshBudget {
    RefreshBudget::try_new(keys, bytes).expect("budget")
}

fn limits() -> RefreshQueueLimits {
    RefreshQueueLimits::try_new(budget(4, 40), budget(2, 20), budget(2, 20), 2).expect("limits")
}

fn ticket(key: u32, generation: u64, demand: Demand, bytes: usize) -> RefreshTicket<u32> {
    RefreshTicket::new(
        key,
        generation,
        RefreshWork::new(
            Instant::now() + Duration::from_secs(30),
            NonZeroUsize::new(bytes).expect("bytes"),
            demand,
        ),
    )
}

#[test]
fn given_invalid_budgets_when_configuring_then_cold_reservations_cannot_be_removed() {
    assert!(RefreshBudget::try_new(0, 1).is_err());
    assert!(RefreshBudget::try_new(1, 0).is_err());
    assert!(RefreshQueueLimits::try_new(budget(4, 40), budget(4, 20), budget(2, 20), 2).is_err());
    assert!(RefreshQueueLimits::try_new(budget(4, 40), budget(2, 40), budget(2, 20), 2).is_err());
    assert!(RefreshQueueLimits::try_new(budget(4, 40), budget(2, 20), budget(5, 20), 2).is_err());
    assert!(RefreshQueueLimits::try_new(budget(4, 40), budget(2, 20), budget(2, 41), 2).is_err());
    assert!(RefreshQueueLimits::try_new(budget(4, 40), budget(2, 20), budget(2, 20), 1).is_err());
}

#[test]
fn given_no_runtime_when_submitting_duplicate_work_then_one_bounded_ticket_is_queued() {
    let queue = RefreshQueue::new(limits());
    assert_eq!(
        queue.try_schedule(ticket(1, 1, Demand::Background, 10)),
        Admission::Queued
    );
    for _ in 0..64 {
        assert_eq!(
            queue.try_schedule(ticket(1, 1, Demand::Background, 10)),
            Admission::Joined
        );
    }
    assert_eq!(queue.stats().queued_keys, 1);
    assert_eq!(queue.stats().active_keys, 0);
    assert_eq!(queue.stats().active_batches, 0);
    assert_eq!(queue.stats().charged_bytes, 10);
    assert_eq!(
        queue.try_schedule(ticket(1, 2, Demand::Cold, 10)),
        Admission::Full
    );
    assert!(!queue.cancel(&1, 2));
    assert!(queue.cancel(&1, 1));
    assert_eq!(
        queue.try_schedule(ticket(1, 2, Demand::Cold, 10)),
        Admission::Queued
    );
}

#[test]
fn given_key_or_byte_pressure_when_background_submits_then_cold_capacity_remains() {
    for bytes in [1, 10] {
        let queue = RefreshQueue::new(limits());
        assert_eq!(
            queue.try_schedule(ticket(1, 1, Demand::Background, bytes)),
            Admission::Queued
        );
        assert_eq!(
            queue.try_schedule(ticket(2, 1, Demand::Background, bytes)),
            Admission::Queued
        );
        assert_eq!(
            queue.try_schedule(ticket(3, 1, Demand::Background, 1)),
            Admission::Full
        );
        assert_eq!(
            queue.try_schedule(ticket(3, 1, Demand::Cold, 10)),
            Admission::Queued
        );
        assert_eq!(
            queue.try_schedule(ticket(4, 1, Demand::Cold, 10)),
            Admission::Queued
        );
        assert_eq!(
            queue.try_schedule(ticket(5, 1, Demand::Cold, 1)),
            Admission::Full
        );
    }
    let queue = RefreshQueue::new(limits());
    assert_eq!(
        queue.try_schedule(ticket(1, 1, Demand::Background, 20)),
        Admission::Queued
    );
    assert_eq!(
        queue.try_schedule(ticket(2, 1, Demand::Background, 1)),
        Admission::Full
    );
    assert_eq!(
        queue.try_schedule(ticket(2, 1, Demand::Cold, 20)),
        Admission::Queued
    );
    assert_eq!(
        queue.try_schedule(ticket(3, 1, Demand::Cold, 1)),
        Admission::Full
    );
    assert_eq!(
        queue.try_schedule(ticket(4, 1, Demand::Cold, 21)),
        Admission::Oversized
    );
}

#[tokio::test]
async fn given_cancelled_active_work_when_resubmitting_then_budget_is_held_until_batch_drop() {
    let queue = RefreshQueue::new(limits());
    queue.try_schedule(ticket(1, 1, Demand::Cold, 20));
    let batch = queue.next_batch(Duration::ZERO).await.expect("batch");
    assert!(queue.cancel(&1, 1));
    assert!(!batch.jobs()[0].is_current());
    tokio::time::timeout(Duration::from_secs(1), batch.cancelled())
        .await
        .expect("cancelled");
    assert_eq!(
        queue.try_schedule(ticket(1, 2, Demand::Cold, 20)),
        Admission::Full
    );
    assert_eq!(queue.stats().active_keys, 1);
    assert_eq!(queue.stats().charged_bytes, 20);
    drop(batch);
    assert_eq!(queue.stats().active_keys, 0);
    assert_eq!(queue.stats().charged_bytes, 0);
    assert_eq!(
        queue.try_schedule(ticket(1, 2, Demand::Cold, 20)),
        Admission::Queued
    );
}

#[tokio::test]
async fn given_one_cancelled_job_when_other_jobs_remain_then_batch_execution_is_not_cancelled() {
    let queue = RefreshQueue::new(limits());
    queue.try_schedule(ticket(1, 1, Demand::Cold, 10));
    queue.try_schedule(ticket(2, 1, Demand::Cold, 10));
    let batch = queue.next_batch(Duration::ZERO).await.expect("batch");
    assert!(queue.cancel(&1, 1));
    assert!(!batch.jobs()[0].is_current());
    assert!(batch.jobs()[1].is_current());
    assert!(
        tokio::time::timeout(Duration::from_millis(5), batch.cancelled())
            .await
            .is_err()
    );
    assert!(queue.cancel(&2, 1));
    tokio::time::timeout(Duration::from_secs(1), batch.cancelled())
        .await
        .expect("cancelled");
    assert_eq!(queue.stats().charged_bytes, 20);
}

#[tokio::test]
async fn given_pending_background_collection_when_cold_joins_then_it_flushes_without_extending_deadline()
 {
    let queue = RefreshQueue::new(limits());
    let original = ticket(1, 1, Demand::Background, 10);
    let deadline = original.deadline();
    assert_eq!(queue.try_schedule(original), Admission::Queued);
    let worker = {
        let queue = queue.clone();
        tokio::spawn(async move { queue.next_batch(Duration::from_secs(3600)).await })
    };
    tokio::task::yield_now().await;
    assert!(!worker.is_finished());
    assert_eq!(
        queue.try_schedule(ticket(1, 1, Demand::Cold, 10)),
        Admission::Joined
    );
    let batch = tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .expect("cold flush")
        .expect("worker")
        .expect("batch");
    assert_eq!(batch.jobs().len(), 1);
    assert_eq!(*batch.jobs()[0].ticket().key(), 1);
    assert_eq!(batch.jobs()[0].ticket().deadline(), deadline);
    assert_eq!(queue.stats().background_keys, 0);
    assert_eq!(queue.stats().charged_bytes, 10);
}

#[tokio::test]
async fn given_active_background_batch_when_cold_arrives_then_reserved_execution_slot_is_available()
{
    let limits = RefreshQueueLimits::try_new(budget(4, 40), budget(2, 20), budget(1, 20), 2)
        .expect("limits");
    let queue = RefreshQueue::new(limits);
    queue.try_schedule(ticket(1, 1, Demand::Background, 10));
    queue.try_schedule(ticket(2, 1, Demand::Background, 10));
    let background = queue.next_batch(Duration::ZERO).await.expect("background");
    let worker = {
        let queue = queue.clone();
        tokio::spawn(async move { queue.next_batch(Duration::ZERO).await })
    };
    tokio::task::yield_now().await;
    assert!(!worker.is_finished());
    queue.try_schedule(ticket(3, 1, Demand::Cold, 10));
    let cold = tokio::time::timeout(Duration::from_secs(1), worker)
        .await
        .expect("cold slot")
        .expect("worker")
        .expect("batch");
    assert_eq!(*cold.jobs()[0].ticket().key(), 3);
    assert_eq!(queue.stats().active_batches, 2);
    drop(background);
    let remaining = queue
        .next_batch(Duration::ZERO)
        .await
        .expect("remaining background");
    assert_eq!(*remaining.jobs()[0].ticket().key(), 2);
    assert_eq!(queue.stats().active_batches, 2);
}

#[tokio::test]
async fn given_batch_key_and_byte_limits_when_draining_then_order_and_total_charges_are_preserved()
{
    for (bytes, expected) in [(1, vec![3, 1]), (10, vec![2, 2])] {
        let limits = RefreshQueueLimits::try_new(budget(10, 100), budget(5, 50), budget(3, 25), 2)
            .expect("limits");
        let queue = RefreshQueue::new(limits);
        for key in 1..=4 {
            assert_eq!(
                queue.try_schedule(ticket(key, 1, Demand::Cold, bytes)),
                Admission::Queued
            );
        }
        let first = queue.next_batch(Duration::ZERO).await.expect("first");
        let second = queue.next_batch(Duration::ZERO).await.expect("second");
        assert_eq!(vec![first.jobs().len(), second.jobs().len()], expected);
        let order: Vec<_> = first
            .jobs()
            .iter()
            .chain(second.jobs())
            .map(|job| *job.ticket().key())
            .collect();
        assert_eq!(order, [1, 2, 3, 4]);
        assert_eq!(queue.stats().charged_bytes, 4 * bytes);
        drop(first);
        drop(second);
        assert_eq!(queue.stats().charged_bytes, 0);
        assert_eq!(queue.stats().active_batches, 0);
    }
}

#[tokio::test]
async fn given_expired_work_when_draining_then_it_cannot_start_or_reuse_active_capacity() {
    let queue = RefreshQueue::new(limits());
    let work = RefreshWork::new(
        Instant::now() - Duration::from_secs(1),
        NonZeroUsize::MIN,
        Demand::Cold,
    );
    assert_eq!(
        queue.try_schedule(RefreshTicket::new(0, 1, work)),
        Admission::Expired
    );
    let deadline = Instant::now() + Duration::from_millis(5);
    queue.try_schedule(RefreshTicket::new(
        1,
        1,
        RefreshWork::new(deadline, NonZeroUsize::MIN, Demand::Cold),
    ));
    tokio::time::sleep(Duration::from_millis(10)).await;
    queue.try_schedule(ticket(2, 1, Demand::Cold, 10));
    let batch = queue.next_batch(Duration::ZERO).await.expect("live batch");
    assert_eq!(batch.jobs().len(), 1);
    assert_eq!(*batch.jobs()[0].ticket().key(), 2);
    drop(batch);
    let deadline = Instant::now() + Duration::from_millis(5);
    queue.try_schedule(RefreshTicket::new(
        3,
        1,
        RefreshWork::new(deadline, NonZeroUsize::MIN, Demand::Cold),
    ));
    let active = queue
        .next_batch(Duration::ZERO)
        .await
        .expect("active batch");
    tokio::time::timeout(Duration::from_secs(1), active.cancelled())
        .await
        .expect("deadline");
    assert!(!active.jobs()[0].is_current());
    assert_eq!(
        queue.try_schedule(ticket(3, 2, Demand::Cold, 1)),
        Admission::Full
    );
    assert_eq!(queue.stats().active_keys, 1);
    drop(active);
    assert_eq!(queue.stats().charged_bytes, 0);
}

#[tokio::test]
async fn given_closed_queue_when_workers_wait_then_pending_work_is_removed_and_active_budget_is_retained()
 {
    let queue = RefreshQueue::new(limits());
    queue.try_schedule(ticket(1, 1, Demand::Cold, 10));
    let batch = queue.next_batch(Duration::ZERO).await.expect("active");
    queue.try_schedule(ticket(2, 1, Demand::Background, 10));
    queue.close();
    assert_eq!(
        queue.try_schedule(ticket(3, 1, Demand::Cold, 10)),
        Admission::Closed
    );
    assert!(queue.next_batch(Duration::ZERO).await.is_none());
    assert_eq!(queue.stats().queued_keys, 0);
    assert_eq!(queue.stats().charged_bytes, 10);
    assert!(queue.stats().closed);
    assert!(!batch.jobs()[0].is_current());
    tokio::time::timeout(Duration::from_secs(1), batch.cancelled())
        .await
        .expect("closed active batch");
    drop(batch);
    assert_eq!(queue.stats().charged_bytes, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn given_cancelled_provider_when_destruction_is_blocked_then_batch_budget_remains_reserved() {
    use std::sync::{Arc, Condvar, Mutex};

    use tokio::sync::Notify;

    use crate::source_drop_test_support::{SourceDropGate, SourceDropRelease};
    let limits = RefreshQueueLimits::try_new(budget(2, 20), budget(1, 10), budget(2, 20), 2)
        .expect("limits");
    let queue = RefreshQueue::new(limits);
    queue.try_schedule(ticket(1, 1, Demand::Cold, 20));
    let started = Arc::new(Notify::new());
    let dropping = Arc::new(Notify::new());
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let _cleanup = SourceDropRelease(Arc::clone(&release));
    let worker = {
        let (queue, started, dropping, release) = (
            queue.clone(),
            Arc::clone(&started),
            Arc::clone(&dropping),
            Arc::clone(&release),
        );
        tokio::spawn(async move {
            let batch = queue.next_batch(Duration::ZERO).await.expect("batch");
            let source = async move {
                let _guard = SourceDropGate { dropping, release };
                started.notify_one();
                std::future::pending::<()>().await;
            };
            tokio::select! { biased; _ = batch.cancelled() => {}, _ = source => {} }
            drop(batch);
        })
    };
    started.notified().await;
    queue.cancel(&1, 1);
    tokio::time::timeout(Duration::from_secs(1), dropping.notified())
        .await
        .expect("provider drop");
    let rejected = queue.try_schedule(ticket(2, 1, Demand::Cold, 1));
    let stats = queue.stats();
    {
        let (lock, condition) = release.as_ref();
        *lock.lock().expect("release") = true;
        condition.notify_all();
    }
    assert_eq!(rejected, Admission::Full);
    assert_eq!(stats.active_keys, 1);
    assert_eq!(stats.charged_bytes, 20);
    worker.await.expect("worker");
    assert_eq!(queue.stats().active_keys, 0);
    assert_eq!(
        queue.try_schedule(ticket(2, 1, Demand::Cold, 1)),
        Admission::Queued
    );
}

#[tokio::test]
async fn given_queued_join_when_requirements_tighten_then_deadline_and_charge_merge() {
    let queue = RefreshQueue::new(limits());
    let original = ticket(1, 1, Demand::Background, 10);
    let earlier = original.deadline() - Duration::from_secs(5);
    assert_eq!(queue.try_schedule(original), Admission::Queued);
    let joined = RefreshTicket::new(
        1,
        1,
        RefreshWork::new(earlier, NonZeroUsize::new(20).unwrap(), Demand::Cold),
    );
    assert_eq!(queue.try_schedule(joined), Admission::Joined);
    assert_eq!(queue.stats().charged_bytes, 20);
    assert_eq!(queue.stats().background_keys, 0);
    let batch = queue.next_batch(Duration::ZERO).await.unwrap();
    assert_eq!(batch.jobs()[0].ticket().deadline(), earlier);
    assert_eq!(
        queue.try_schedule(ticket(1, 1, Demand::Cold, 10)),
        Admission::Joined
    );
    let stricter = RefreshTicket::new(
        1,
        1,
        RefreshWork::new(
            earlier - Duration::from_secs(1),
            NonZeroUsize::new(10).unwrap(),
            Demand::Cold,
        ),
    );
    assert_eq!(queue.try_schedule(stricter), Admission::Full);
}

#[tokio::test]
async fn given_background_budget_full_when_join_grows_then_original_ticket_is_unchanged() {
    let queue = RefreshQueue::new(limits());
    let original = ticket(1, 1, Demand::Background, 10);
    let deadline = original.deadline();
    assert_eq!(queue.try_schedule(original), Admission::Queued);
    assert_eq!(
        queue.try_schedule(ticket(2, 1, Demand::Background, 10)),
        Admission::Queued
    );
    let larger = RefreshTicket::new(
        1,
        1,
        RefreshWork::new(
            deadline - Duration::from_secs(1),
            NonZeroUsize::new(20).unwrap(),
            Demand::Background,
        ),
    );
    assert_eq!(queue.try_schedule(larger), Admission::Full);
    assert_eq!(queue.stats().charged_bytes, 20);
    let batch = queue.next_batch(Duration::ZERO).await.unwrap();
    assert_eq!(batch.jobs()[0].ticket().deadline(), deadline);
    assert_eq!(
        queue.try_schedule(ticket(1, 1, Demand::Background, 20)),
        Admission::Full
    );
}

#[test]
fn given_cold_work_when_background_join_grows_then_reserved_bytes_are_preserved() {
    let queue = RefreshQueue::new(limits());
    assert_eq!(
        queue.try_schedule(ticket(1, 1, Demand::Cold, 10)),
        Admission::Queued
    );
    assert_eq!(
        queue.try_schedule(ticket(1, 1, Demand::Background, 20)),
        Admission::Full
    );
    assert_eq!(queue.stats().charged_bytes, 10);
    assert_eq!(
        queue.try_schedule(ticket(2, 1, Demand::Background, 10)),
        Admission::Queued
    );
    assert_eq!(
        queue.try_schedule(ticket(3, 1, Demand::Background, 10)),
        Admission::Queued
    );
    assert_eq!(
        queue.try_schedule(ticket(4, 1, Demand::Cold, 10)),
        Admission::Queued
    );
    assert_eq!(queue.stats().charged_bytes, 40);
}
