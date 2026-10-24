use std::{collections::HashMap, num::NonZeroU16, sync::Arc, time::Duration};

use crate::{
    error::ValidationError,
    ids::{JobKind, QueueName},
    model::{HandlerDefinition, JobHandler},
    policy::{EffectMode, FairnessPolicy, RetrySelection},
};

/// An immutable registration snapshot used by the lifecycle engine.
#[derive(Clone)]
pub struct HandlerRegistration {
    kind: JobKind,
    schema_version: NonZeroU16,
    queue: QueueName,
    effect_mode: EffectMode,
    cost_units: NonZeroU16,
    fairness_policy: FairnessPolicy,
    default_retry: RetrySelection,
    default_timeout: Duration,
    handler: Arc<dyn JobHandler>,
}

impl HandlerRegistration {
    pub(crate) fn queue(&self) -> &QueueName {
        &self.queue
    }

    pub(crate) const fn effect_mode(&self) -> EffectMode {
        self.effect_mode
    }

    pub(crate) const fn cost_units(&self) -> NonZeroU16 {
        self.cost_units
    }

    pub(crate) const fn fairness_policy(&self) -> FairnessPolicy {
        self.fairness_policy
    }

    pub(crate) const fn default_retry(&self) -> RetrySelection {
        self.default_retry
    }

    pub(crate) const fn default_timeout(&self) -> Duration {
        self.default_timeout
    }

    pub(crate) fn handler(&self) -> &Arc<dyn JobHandler> {
        &self.handler
    }
}

impl std::fmt::Debug for HandlerRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HandlerRegistration")
            .field("kind", &self.kind)
            .field("schema_version", &self.schema_version)
            .field("queue", &self.queue)
            .field("effect_mode", &self.effect_mode)
            .field("cost_units", &self.cost_units)
            .field("fairness_policy", &self.fairness_policy)
            .field("default_retry", &self.default_retry)
            .field("default_timeout", &self.default_timeout)
            .finish_non_exhaustive()
    }
}

/// A registry that is mutable while being assembled and snapshotted by
/// `JobSystem` at creation.
#[derive(Clone, Default)]
pub struct HandlerRegistry {
    registrations: Arc<HashMap<NonZeroU16, HashMap<JobKind, HandlerRegistration>>>,
}

impl std::fmt::Debug for HandlerRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HandlerRegistry")
            .field("registration_count", &self.len())
            .finish()
    }
}

impl HandlerRegistry {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<H>(&mut self, definition: HandlerDefinition<H>) -> Result<(), ValidationError>
    where H: JobHandler {
        definition.validate()?;
        let registrations = Arc::make_mut(&mut self.registrations);
        let by_kind = registrations.entry(definition.schema_version).or_default();
        if by_kind.contains_key(&definition.kind) {
            return Err(ValidationError::InvalidValue {
                field: "duplicate handler registration",
            });
        }
        by_kind.insert(
            definition.kind.clone(),
            HandlerRegistration {
                kind: definition.kind,
                schema_version: definition.schema_version,
                queue: definition.queue,
                effect_mode: definition.effect_mode,
                cost_units: definition.cost_units,
                fairness_policy: definition.fairness_policy,
                default_retry: definition.default_retry,
                default_timeout: definition.default_timeout,
                handler: Arc::new(definition.handler),
            },
        );
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn test_handler_identities(&self) -> impl Iterator<Item = (&JobKind, NonZeroU16)> {
        self.registrations.values().flat_map(|by_kind| {
            by_kind
                .values()
                .map(|registration| (&registration.kind, registration.schema_version))
        })
    }

    pub(crate) fn get_ref(
        &self,
        kind: &JobKind,
        schema_version: NonZeroU16,
    ) -> Option<&HandlerRegistration> {
        self.registrations.get(&schema_version)?.get(kind)
    }

    pub fn contains(&self, kind: &JobKind, schema_version: NonZeroU16) -> bool {
        self.get_ref(kind, schema_version).is_some()
    }

    pub fn len(&self) -> usize {
        self.registrations.values().map(HashMap::len).sum()
    }
}
