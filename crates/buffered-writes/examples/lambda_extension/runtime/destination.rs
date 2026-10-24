use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use buffered_writes::{
    ConfigurationError, PartialSink, SinkError, SinkLimits, WriteAttempt, WriteOutcome,
};

/// Volatile idempotent maximum register, solely for lifecycle demonstration.
pub(super) struct DemoDestination {
    pub(super) sink: PartialSink<u64>,
    pub(super) maximum: Arc<AtomicU64>,
}

impl DemoDestination {
    pub(super) fn try_new(delay: Duration) -> Result<Self, ConfigurationError> {
        let maximum = Arc::new(AtomicU64::new(0));
        let observed = maximum.clone();
        let sink = PartialSink::try_new(
            SinkLimits::default(),
            move |attempt: WriteAttempt<u64>| {
                let maximum = observed.clone();
                async move {
                    tokio::time::sleep(delay).await;
                    for item in attempt.pending_items() {
                        maximum.fetch_max(*item.item(), Ordering::SeqCst);
                    }
                    println!(
                        "{}",
                        serde_json::json!({"event":"applied", "batch_id":attempt.batch_id().to_string(), "maximum":maximum.load(Ordering::SeqCst), "items":attempt.items().len()})
                    );
                    Ok::<_, SinkError>(WriteOutcome::Complete)
                }
            },
        )?;
        Ok(Self { sink, maximum })
    }
}
