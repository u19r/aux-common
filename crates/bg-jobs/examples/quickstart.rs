use std::num::NonZeroU16;

use bg_jobs::{
    EffectMode, FairnessPolicy, HandlerFuture, JobCatalog, JobHandler, JobKind, JobOutcome,
    JobSpec, QueueName, RetryPreset, RetrySelection,
};

struct ExampleHandler;

impl JobHandler for ExampleHandler {
    fn execute<'a>(
        &'a self,
        _context: bg_jobs::ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        Box::pin(async { Ok(JobOutcome::Cancelled) })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut catalog = JobCatalog::new();
    let handle = catalog.register(
        JobSpec::bytes(
            JobKind::try_new("example.job")?,
            NonZeroU16::MIN,
            QueueName::try_new("example")?,
            ExampleHandler,
        )
        .policy(
            EffectMode::Idempotent,
            FairnessPolicy::low_volume(),
            RetrySelection::Preset(RetryPreset::Interactive),
            std::time::Duration::from_secs(1),
        ),
    )?;

    assert_eq!(handle.kind().as_str(), "example.job");
    Ok(())
}
