use std::sync::Arc;

use serde::{Serialize, de::DeserializeOwned};

use super::worker::ReplayWorker;
use crate::{
    Clock, ConfigurationError, DeliveryPolicy, NoopWriteObserver, ProductionClock, RecordCodec,
    ReplayGuarantee, ReplayQueue, SerdeJsonCodec, WriteObserver, WriteSink,
    constants::DEFAULT_GROUPING_STRATEGY_VERSION,
};

/// Replay configuration with default encoding and bounded delivery policy.
pub struct ReplayBuilder<T> {
    namespace: String,
    strategy_version: String,
    queue: Arc<dyn ReplayQueue>,
    sink: Arc<dyn WriteSink<T>>,
    codec: Arc<dyn RecordCodec<T>>,
    policy: DeliveryPolicy,
    clock: Arc<dyn Clock>,
    observer: Arc<dyn WriteObserver>,
}

impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> ReplayBuilder<T> {
    pub(super) fn new(namespace: String, queue: impl ReplayQueue, sink: impl WriteSink<T>) -> Self {
        Self {
            namespace,
            strategy_version: DEFAULT_GROUPING_STRATEGY_VERSION.to_owned(),
            queue: Arc::new(queue),
            sink: Arc::new(sink),
            codec: Arc::new(SerdeJsonCodec::<T>::default()),
            policy: DeliveryPolicy::default(),
            clock: Arc::new(ProductionClock),
            observer: Arc::new(NoopWriteObserver),
        }
    }
}

impl<T: Send + Sync + 'static> ReplayBuilder<T> {
    #[must_use]
    pub fn strategy_version(mut self, version: impl Into<String>) -> Self {
        self.strategy_version = version.into();
        self
    }
    #[must_use]
    pub fn with_codec(mut self, codec: impl RecordCodec<T>) -> Self {
        self.codec = Arc::new(codec);
        self
    }
    #[must_use]
    pub fn delivery_policy(mut self, policy: DeliveryPolicy) -> Self {
        self.policy = policy;
        self
    }
    #[must_use]
    pub fn with_clock(mut self, clock: impl Clock) -> Self {
        self.clock = Arc::new(clock);
        self
    }
    #[must_use]
    pub fn with_observer(mut self, observer: impl WriteObserver) -> Self {
        self.observer = Arc::new(observer);
        self
    }
    pub fn build(self) -> Result<ReplayWorker<T>, ConfigurationError> {
        let namespace = self.namespace.try_into()?;
        self.policy.validate()?;
        self.sink.limits().validate()?;
        if self.sink.replay_guarantee() == ReplayGuarantee::Unsupported {
            return Err(ConfigurationError::UnsupportedReplayGuarantee);
        }
        crate::configuration::validate_version(&self.strategy_version)?;
        crate::configuration::validate_version(self.codec.version())?;
        Ok(ReplayWorker {
            namespace,
            strategy_version: self.strategy_version,
            queue: self.queue,
            sink: self.sink,
            codec: self.codec,
            policy: self.policy,
            clock: self.clock,
            observer: self.observer,
        })
    }
}
