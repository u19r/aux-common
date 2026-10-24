use crate::{
    error::ValidationError,
    model::{HandlerDefinition, JobHandle, JobHandler, JobSeed, JobSpec, NewJob},
    registry::HandlerRegistry,
};

/// A runtime-neutral composition of handler registrations and stable seeds.
///
/// The catalog validates only the relationship between a handler definition and
/// its optional seed. Roles, configuration, routes, storage, and external
/// effects remain owned by the consuming application.
#[derive(Clone, Debug, Default)]
pub struct JobCatalog {
    registry: HandlerRegistry,
    seeds: Vec<NewJob>,
}

impl JobCatalog {
    #[cfg(test)]
    pub(crate) fn from_registry(registry: HandlerRegistry) -> Self {
        Self {
            registry,
            seeds: Vec::new(),
        }
    }
    /// Creates an empty catalog.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a typed handler specification and returns its enqueue handle.
    pub fn register<T: 'static, H>(
        &mut self,
        spec: JobSpec<T, H>,
    ) -> Result<JobHandle<T>, ValidationError>
    where
        H: JobHandler,
    {
        let (definition, handle) = spec.into_parts()?;
        self.registry.register(definition)?;
        Ok(handle)
    }

    /// Registers a typed handler and its stable seed as one operation.
    ///
    /// This is the routine path for controller jobs: the catalog validates the
    /// specification and seed before mutating either registration or seed
    /// state, so a malformed seed cannot leave a partially assembled catalog.
    pub fn register_seeded<T: 'static, H>(
        &mut self,
        spec: JobSpec<T, H>,
        payload: T,
        options: crate::model::EnqueueOptions,
        now: crate::time::Timestamp,
    ) -> Result<JobHandle<T>, ValidationError>
    where
        H: JobHandler,
    {
        let (definition, handle) = spec.into_parts()?;
        let job_id = options
            .job_id_value()
            .ok_or(ValidationError::InvalidValue {
                field: "seed job id",
            })?;
        let seed = handle.new_job(payload, options, job_id, now)?;
        validate_seed_identity(&definition, &seed)?;
        self.validate_new_seed(&seed)?;
        self.registry.register(definition)?;
        self.seeds.push(seed);
        Ok(handle)
    }

    /// Registers a raw handler and optional seed for test/conformance
    /// callers. Routine consumers should use [`Self::register`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn register_raw<H>(
        &mut self,
        definition: HandlerDefinition<H>,
        seed: Option<NewJob>,
    ) -> Result<(), ValidationError>
    where
        H: JobHandler,
    {
        if let Some(seed) = seed.as_ref() {
            validate_seed_identity(&definition, seed)?;
            self.validate_new_seed(seed)?;
        }
        self.registry.register(definition)?;
        if let Some(seed) = seed {
            self.seeds.push(seed);
        }
        Ok(())
    }

    /// Adds a raw stable seed for test/conformance callers.
    #[cfg(any(test, feature = "test-support"))]
    pub fn add_seed_raw(&mut self, seed: NewJob) -> Result<(), ValidationError> {
        self.add_seed_impl(seed)
    }

    /// Adds a stable seed produced by a typed handler handle.
    pub fn add_seed_value(&mut self, seed: JobSeed) -> Result<(), ValidationError> {
        self.add_seed_impl(seed.into_new_job())
    }

    fn add_seed_impl(&mut self, seed: NewJob) -> Result<(), ValidationError> {
        if !self.registry.contains(&seed.kind, seed.schema_version) {
            return Err(ValidationError::InvalidValue {
                field: "seed handler identity",
            });
        }
        self.validate_new_seed(&seed)?;
        self.seeds.push(seed);
        Ok(())
    }

    /// Inspect actual registrations in consumer composition tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_handler_identities(
        &self,
    ) -> impl Iterator<Item = (&crate::ids::JobKind, std::num::NonZeroU16)> {
        self.registry.test_handler_identities()
    }

    pub(crate) fn into_parts(self) -> (HandlerRegistry, Vec<NewJob>) {
        (self.registry, self.seeds)
    }

    fn validate_new_seed(&self, seed: &NewJob) -> Result<(), ValidationError> {
        seed.validate()?;
        if self
            .seeds
            .iter()
            .any(|existing| existing.job_id == seed.job_id)
        {
            return Err(ValidationError::InvalidValue {
                field: "duplicate seed job id",
            });
        }
        Ok(())
    }
}

fn validate_seed_identity<H>(
    definition: &HandlerDefinition<H>,
    seed: &NewJob,
) -> Result<(), ValidationError> {
    if definition.kind != seed.kind || definition.schema_version != seed.schema_version {
        return Err(ValidationError::InvalidValue {
            field: "seed handler identity",
        });
    }
    Ok(())
}
