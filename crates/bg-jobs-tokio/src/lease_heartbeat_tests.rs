use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::sync::{Notify, Semaphore};

use crate::LeaseHeartbeat;

#[tokio::test(start_paused = true)]
async fn given_a_long_operation_when_renewals_succeed_then_its_output_is_preserved() {
    let renewals = AtomicUsize::new(0);
    let result = LeaseHeartbeat::CancelOnLoss(Duration::from_secs(1))
        .run(
            async {
                tokio::time::sleep(Duration::from_millis(3500)).await;
                42
            },
            || async {
                renewals.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &'static str>(())
            },
        )
        .await;
    assert_eq!(result, Ok(42));
    assert_eq!(renewals.load(Ordering::SeqCst), 3);
}

#[tokio::test(start_paused = true)]
async fn given_a_read_operation_when_renewal_fails_then_it_is_dropped() {
    let mut completed = false;
    let result = LeaseHeartbeat::CancelOnLoss(Duration::from_secs(1))
        .run(
            async {
                tokio::time::sleep(Duration::from_secs(2)).await;
                completed = true;
            },
            || async { Err("lost") },
        )
        .await;
    assert_eq!(result, Err("lost"));
    assert!(!completed);
}

#[tokio::test(start_paused = true)]
async fn given_an_in_flight_write_when_renewal_fails_then_loss_waits_for_the_write_to_settle() {
    let gate = Arc::new(Semaphore::new(0));
    let renewed = Arc::new(Notify::new());
    let completed = Arc::new(AtomicUsize::new(0));
    let operation_gate = gate.clone();
    let operation_completed = completed.clone();
    let renewal_notification = renewed.clone();
    let running = tokio::spawn(async move {
        LeaseHeartbeat::DrainOnLoss(Duration::from_secs(1))
            .run(
                async move {
                    operation_gate.acquire().await.unwrap().forget();
                    operation_completed.fetch_add(1, Ordering::SeqCst);
                    "committed"
                },
                || async {
                    renewal_notification.notify_one();
                    Err("lost")
                },
            )
            .await
    });
    renewed.notified().await;
    assert!(!running.is_finished());
    assert_eq!(completed.load(Ordering::SeqCst), 0);
    gate.add_permits(1);
    assert_eq!(running.await.unwrap(), Err("lost"));
    assert_eq!(completed.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn given_a_completed_operation_when_a_renewal_is_due_then_no_extra_renewal_runs() {
    let renewals = AtomicUsize::new(0);
    let operation = tokio::time::sleep(Duration::from_secs(1));
    let result = LeaseHeartbeat::CancelOnLoss(Duration::from_secs(1))
        .run(operation, || async {
            renewals.fetch_add(1, Ordering::SeqCst);
            Err("lost")
        })
        .await;
    assert_eq!(result, Ok(()));
    assert_eq!(renewals.load(Ordering::SeqCst), 0);
}
