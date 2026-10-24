use std::sync::{Arc, Mutex};

use serde::{Serialize, de::DeserializeOwned};

use super::{builder::WritesBuilder, driver::DriverHandleState};
use crate::{
    batch::ScopedWrite,
    configuration::{Admission, Deadline, Namespace, WriteOptions},
    engine::Engine,
    error::{EncodeError, WriteError},
    observer::{DeliveryMode, DrainReport, FlushReport, SinkHealth},
    write_sink::WriteSink,
};
/// Cloneable buffered write handle hiding provider, clock, observer, and queue
/// generics.
pub struct BufferedWrites<T> {
    pub(super) engine: Arc<Engine<T>>,
    pub(super) driver_state: Arc<Mutex<Option<DriverHandleState>>>,
}

impl<T> Clone for BufferedWrites<T> {
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            driver_state: self.driver_state.clone(),
        }
    }
}

impl<T> std::fmt::Debug for BufferedWrites<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BufferedWrites")
            .field("namespace", &self.engine.cfg.namespace)
            .finish()
    }
}

impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> BufferedWrites<T> {
    #[must_use]
    pub fn builder(namespace: impl Into<String>, sink: impl WriteSink<T>) -> WritesBuilder<T> {
        WritesBuilder::new(namespace.into(), sink)
    }
}

impl<T: Send + Sync + 'static> BufferedWrites<T> {
    #[cfg(feature = "lambda")]
    pub(crate) fn clone_observer(&self) -> Arc<dyn crate::WriteObserver> {
        Arc::clone(&self.engine.cfg.observer)
    }

    pub(crate) fn from_engine(engine: Arc<Engine<T>>) -> Self {
        Self {
            engine,
            driver_state: Arc::new(Mutex::new(None)),
        }
    }

    #[must_use]
    pub fn namespace(&self) -> &Namespace {
        &self.engine.cfg.namespace
    }

    #[must_use]
    pub fn mode_and_health(&self) -> (DeliveryMode, SinkHealth) {
        self.engine.mode_and_health()
    }

    pub async fn add_write_item(&self, item: T) -> Result<Admission, WriteError> {
        self.add_write_item_with_options(item, WriteOptions::new())
            .await
    }

    pub async fn add_scoped_write(&self, scoped: ScopedWrite<T>) -> Result<Admission, WriteError> {
        let (scope, item) = scoped.into_parts();
        self.add_write_item_with_options(item, WriteOptions::new().with_scope(scope))
            .await
    }

    pub async fn add_write_item_with_options(
        &self,
        item: T,
        options: WriteOptions,
    ) -> Result<Admission, WriteError> {
        self.engine.admit_factory(|| Ok(item), options).await
    }

    pub async fn add_write_item_with<F>(&self, create: F) -> Result<Admission, WriteError>
    where F: FnOnce() -> Result<T, EncodeError> + Send {
        self.add_write_item_with_and_options(create, WriteOptions::new())
            .await
    }

    pub async fn add_write_item_with_and_options<F>(
        &self,
        create: F,
        options: WriteOptions,
    ) -> Result<Admission, WriteError>
    where
        F: FnOnce() -> Result<T, EncodeError> + Send,
    {
        self.engine.admit_factory(create, options).await
    }

    pub async fn after_response(&self) -> FlushReport {
        self.engine.after_response().await
    }

    pub async fn flush_writes(&self) -> FlushReport {
        self.engine.flush_writes().await
    }

    pub async fn shutdown(&self, deadline: impl Into<Deadline>) -> DrainReport {
        let deadline = deadline.into();
        let report = self.engine.shutdown(deadline).await;
        self.complete_attached_driver(deadline).await;
        report
    }
}
