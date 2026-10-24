use std::sync::Arc;

use crate::{
    catalog::JobCatalog,
    engine::JobSystem,
    error::{StoreContractError, ValidationError},
    ids::{Namespace, OwnerId},
    model::WakeScheduler,
    observer::{JobObserver, NoopObserver},
    store::JobStore,
};

type BuilderParts<S> = (
    S,
    JobCatalog,
    Namespace,
    OwnerId,
    Arc<dyn WakeScheduler>,
    Arc<dyn JobObserver>,
);

/// Named construction inputs for a runtime-owned job system.
pub struct JobSystemBuilder<S: JobStore> {
    store: S,
    catalog: JobCatalog,
    namespace: Option<Namespace>,
    owner: Option<OwnerId>,
    scheduler: Option<Arc<dyn WakeScheduler>>,
    observer: Arc<dyn JobObserver>,
}

impl<S: JobStore> JobSystemBuilder<S> {
    /// Starts a builder with an empty catalog and a no-op observer.
    pub fn new(store: S) -> Self {
        Self {
            store,
            catalog: JobCatalog::new(),
            namespace: None,
            owner: None,
            scheduler: None,
            observer: Arc::new(NoopObserver),
        }
    }

    /// Replaces the handler registrations and stable startup seeds with a
    /// validated application catalog.
    pub fn catalog(mut self, catalog: JobCatalog) -> Self {
        self.catalog = catalog;
        self
    }

    /// Sets the durable namespace for this system.
    pub fn namespace(mut self, namespace: Namespace) -> Self {
        self.namespace = Some(namespace);
        self
    }

    /// Sets the owner identity used for leases and fencing.
    pub fn owner(mut self, owner: OwnerId) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Sets the caller-owned runtime wake scheduler.
    pub fn scheduler(mut self, scheduler: Arc<dyn WakeScheduler>) -> Self {
        self.scheduler = Some(scheduler);
        self
    }

    /// Installs a non-blocking lifecycle observer.
    pub fn with_observer(mut self, observer: Arc<dyn JobObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Builds a system after validating all required inputs.
    pub fn build(self) -> Result<JobSystem<S>, ValidationError> {
        let (store, catalog, namespace, owner, scheduler, observer) = self.into_parts()?;

        Ok(JobSystem::new(store, catalog, namespace, owner, scheduler).with_observer(observer))
    }

    /// Builds a system only when the supplied store proves distributed
    /// semantics.
    pub fn build_distributed(self) -> Result<JobSystem<S>, StoreContractError> {
        let (store, catalog, namespace, owner, scheduler, observer) = self.into_parts()?;
        Ok(
            JobSystem::try_new_distributed(store, catalog, namespace, owner, scheduler)?
                .with_observer(observer),
        )
    }

    fn into_parts(self) -> Result<BuilderParts<S>, ValidationError> {
        let namespace = self.namespace.ok_or(ValidationError::InvalidValue {
            field: "job system namespace",
        })?;
        let owner = self.owner.ok_or(ValidationError::InvalidValue {
            field: "job system owner",
        })?;
        let scheduler = self.scheduler.ok_or(ValidationError::InvalidValue {
            field: "job system wake scheduler",
        })?;
        Ok((
            self.store,
            self.catalog,
            namespace,
            owner,
            scheduler,
            self.observer,
        ))
    }
}
