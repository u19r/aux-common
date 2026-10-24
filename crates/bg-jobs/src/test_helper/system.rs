use std::{num::NonZeroU16, sync::Arc, time::Duration};

use super::{fake_store::FakeStore, handler::CompletingHandler};
use crate::{
    EffectMode, FairnessPolicy, HandlerDefinition, HandlerRegistry, JobKind, JobSystem, Namespace,
    OwnerId, QueueName, RetryPreset, WakeFuture, WakeScheduler, WakeSchedulerError,
};

pub(crate) fn registry(policy: FairnessPolicy) -> HandlerRegistry {
    let kind = JobKind::try_new("email").expect("test kind is valid");
    let queue = QueueName::try_new("default").expect("test queue is valid");
    let mut registry = HandlerRegistry::default();
    registry
        .register(HandlerDefinition {
            kind,
            schema_version: NonZeroU16::new(1).expect("schema is non-zero"),
            queue,
            effect_mode: EffectMode::Idempotent,
            cost_units: NonZeroU16::new(1).expect("cost is non-zero"),
            fairness_policy: policy,
            // Lifecycle fixtures exercise a short, explicit exhaustion
            // boundary.
            default_retry: RetryPreset::Interactive
                .with_limits(NonZeroU16::new(3).unwrap(), Duration::from_secs(5))
                .expect("fixture retry limits"),
            default_timeout: Duration::from_secs(1),
            handler: CompletingHandler,
        })
        .expect("test registration is valid");
    registry
}

pub(crate) fn system(store: FakeStore, policy: FairnessPolicy, owner: u8) -> JobSystem<FakeStore> {
    JobSystem::new(
        store,
        crate::JobCatalog::from_registry(registry(policy)),
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        OwnerId::from([owner; 16]),
        wake_scheduler(),
    )
}

struct ImmediateWakeScheduler;

impl WakeScheduler for ImmediateWakeScheduler {
    fn sleep(&self, _delay: Duration) -> Result<WakeFuture, WakeSchedulerError> {
        Ok(Box::pin(std::future::ready(())))
    }
}

pub(crate) fn wake_scheduler() -> Arc<dyn WakeScheduler> {
    Arc::new(ImmediateWakeScheduler)
}
