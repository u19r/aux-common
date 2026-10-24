use std::time::Duration;

use bg_jobs::runtime::WakeScheduler;

use crate::scheduler::TokioWakeScheduler;

#[test]
fn given_no_tokio_runtime_when_sleeping_then_unavailable_is_reported() {
    assert!(matches!(
        TokioWakeScheduler.sleep(Duration::ZERO),
        Err(bg_jobs::runtime::WakeSchedulerError::Unavailable)
    ));
}

#[test]
fn given_a_tokio_runtime_when_sleeping_then_the_wake_future_resolves() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("test runtime builds");

    runtime.block_on(async {
        TokioWakeScheduler
            .sleep(Duration::ZERO)
            .expect("tokio scheduler is available")
            .await;
    });
}
