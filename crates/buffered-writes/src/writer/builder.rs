use std::{sync::Arc, time::Duration};

use serde::{Serialize, de::DeserializeOwned};

use super::handle::BufferedWrites;
use crate::{
    batch::{
        BatchItems, ClosureWriteBatch, DefaultItemGrouping, PreparationLimits, PreparedWrites,
        RecordCodec, SerdeJsonCodec, WriteBatch,
    },
    buffer::WriteBuffer,
    configuration::{
        BufferCapacity, BufferConfig, DeliveryPolicy, FlushPolicy, FlushThresholds, Namespace,
        SinkLimits, TenantScope,
    },
    engine::{Engine, EngineConfig, ScopeExtractor},
    error::{ConfigurationError, PrepareError, WriteError},
    memory_buffer::MemoryBuffer,
    observer::{Clock, NoopWriteObserver, ProductionClock, WriteObserver},
    queue::{QueueConfig, QueueConfigKind, WriteQueue},
    write_sink::{ReplayGuarantee, WriteSink},
};
/// Validated builder for [`BufferedWrites<T>`].
pub struct WritesBuilder<T> {
    namespace: String,
    sink: Arc<dyn WriteSink<T>>,
    codec: Arc<dyn RecordCodec<T>>,
    batch_strategy: Result<Arc<dyn WriteBatch<T>>, ConfigurationError>,
    buffer_config: BufferConfig,
    custom_buffer: Option<Arc<dyn WriteBuffer>>,
    flush_policy: Arc<dyn FlushPolicy>,
    capacity: BufferCapacity,
    delivery_policy: DeliveryPolicy,
    periodic_interval: Option<Duration>,
    queue_config: Option<QueueConfig>,
    scope_extractor: Option<ScopeExtractor<T>>,
    clock: Arc<dyn Clock>,
    observer: Arc<dyn WriteObserver>,
}

impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> WritesBuilder<T> {
    pub(crate) fn new(namespace: String, sink: impl WriteSink<T>) -> Self {
        Self::new_with_codec(namespace, sink, SerdeJsonCodec::<T>::default())
    }
}

impl<T: Send + Sync + 'static> WritesBuilder<T> {
    pub(crate) fn new_with_codec(
        namespace: String,
        sink: impl WriteSink<T>,
        codec: impl RecordCodec<T>,
    ) -> Self {
        Self {
            namespace,
            sink: Arc::new(sink),
            codec: Arc::new(codec),
            batch_strategy: Ok(Arc::new(DefaultItemGrouping)),
            buffer_config: BufferConfig::Memory,
            custom_buffer: None,
            flush_policy: Arc::new(FlushThresholds::default()),
            capacity: BufferCapacity::default(),
            delivery_policy: DeliveryPolicy::default(),
            periodic_interval: None,
            queue_config: None,
            scope_extractor: None,
            clock: Arc::new(ProductionClock),
            observer: Arc::new(NoopWriteObserver),
        }
    }

    #[must_use]
    pub fn buffer(mut self, config: BufferConfig) -> Self {
        self.buffer_config = config;
        self.custom_buffer = None;
        self
    }

    #[must_use]
    pub fn with_buffer_provider(mut self, provider: impl WriteBuffer) -> Self {
        self.custom_buffer = Some(Arc::new(provider));
        self
    }

    #[must_use]
    pub fn flush_policy(mut self, policy: impl FlushPolicy + 'static) -> Self {
        self.flush_policy = Arc::new(policy);
        self
    }

    #[must_use]
    pub fn buffer_capacity(mut self, capacity: BufferCapacity) -> Self {
        self.capacity = capacity;
        self
    }

    #[must_use]
    pub fn periodic_flush(mut self, interval: Duration) -> Self {
        self.periodic_interval = Some(interval);
        self
    }

    #[must_use]
    pub fn fallback(mut self, queue: QueueConfig) -> Self {
        self.queue_config = Some(queue);
        self
    }

    #[must_use]
    pub fn delivery_policy(mut self, policy: DeliveryPolicy) -> Self {
        self.delivery_policy = policy;
        self
    }

    #[must_use]
    pub fn allow_queue_success(mut self, allow: bool) -> Self {
        self.delivery_policy.allow_queue_success = allow;
        self
    }

    #[must_use]
    pub fn codec(mut self, codec: impl RecordCodec<T>) -> Self {
        self.codec = Arc::new(codec);
        self
    }

    #[must_use]
    pub fn scope_extractor<F>(mut self, extractor: F) -> Self
    where F: Fn(&T) -> Result<TenantScope, WriteError> + Send + Sync + 'static {
        self.scope_extractor = Some(Arc::new(extractor));
        self
    }

    #[must_use]
    pub fn prepare_with<F>(mut self, version: impl Into<String>, prepare: F) -> Self
    where F: Fn(BatchItems<'_, T>) -> Result<PreparedWrites, PrepareError> + Send + Sync + 'static
    {
        self.batch_strategy = ClosureWriteBatch::try_new(version, prepare)
            .map(|strategy| Arc::new(strategy) as Arc<dyn WriteBatch<T>>);
        self
    }

    #[must_use]
    pub fn with_batch_strategy(mut self, strategy: impl WriteBatch<T>) -> Self {
        self.batch_strategy = Ok(Arc::new(strategy));
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
}

impl<T: Send + Sync + 'static> WritesBuilder<T> {
    pub fn build(self) -> Result<BufferedWrites<T>, ConfigurationError> {
        let namespace = self.validate_configuration()?;
        let strategy = self.batch_strategy.as_ref().map_err(Clone::clone)?;
        let buffer = self.resolve_buffer(&namespace)?;
        if buffer.namespace() != &namespace {
            return Err(ConfigurationError::NamespaceMismatch);
        }
        let queue = self.resolve_queue()?;
        if self.delivery_policy.allow_queue_success {
            let Some(ref q) = queue else {
                return Err(ConfigurationError::InvalidQueueConfiguration {
                    reason: "allow_queue_success requires a configured fallback queue",
                });
            };
            if !q.limits().is_independent_failure_domain() {
                return Err(ConfigurationError::InvalidQueueConfiguration {
                    reason: "allow_queue_success requires an independent queue failure domain",
                });
            }
        }
        let effective_limits = self.compute_effective_limits(queue.as_deref())?;
        let preparation =
            PreparationLimits::new(strategy.layout(), &self.capacity, &effective_limits);
        let engine = Arc::new(Engine::new(EngineConfig {
            namespace,
            scope_extractor: self.scope_extractor,
            codec: self.codec,
            batch_strategy: self.batch_strategy?,
            buffer,
            sink: self.sink,
            queue,
            flush_policy: self.flush_policy,
            capacity: self.capacity,
            delivery_policy: self.delivery_policy,
            effective_limits,
            preparation,
            clock: self.clock,
            observer: self.observer,
            periodic_interval: self.periodic_interval,
        }));
        Ok(BufferedWrites::from_engine(engine))
    }

    fn validate_configuration(&self) -> Result<Namespace, ConfigurationError> {
        let namespace = Namespace::try_new(self.namespace.clone())?;
        let strategy = self.batch_strategy.as_ref().map_err(Clone::clone)?;
        crate::configuration::validate_version(self.codec.version())?;
        crate::configuration::validate_version(strategy.strategy_version())?;
        self.flush_policy.validate()?;
        if self.sink.replay_guarantee() == ReplayGuarantee::Unsupported {
            return Err(ConfigurationError::UnsupportedReplayGuarantee);
        }
        self.sink.limits().validate()?;
        self.capacity.validate()?;
        self.delivery_policy.validate()?;
        if self.periodic_interval.is_some_and(|i| i.is_zero()) {
            return Err(ConfigurationError::ZeroCapacity {
                field: "periodic_flush",
            });
        }
        Ok(namespace)
    }

    fn resolve_buffer(
        &self,
        namespace: &Namespace,
    ) -> Result<Arc<dyn WriteBuffer>, ConfigurationError> {
        if let Some(custom) = &self.custom_buffer {
            return Ok(Arc::clone(custom));
        }
        match &self.buffer_config {
            BufferConfig::Memory => Ok(Arc::new(MemoryBuffer::new(namespace.clone()))),
            BufferConfig::Disk { directory } => {
                #[cfg(feature = "disk")]
                {
                    let disk =
                        crate::disk_buffer::DiskBuffer::open(namespace.clone(), directory.clone())?;
                    Ok(Arc::new(disk))
                }
                #[cfg(not(feature = "disk"))]
                {
                    let _ = (directory, namespace);
                    Err(ConfigurationError::InvalidDiskPath {
                        reason: "disk feature is not enabled",
                    })
                }
            }
            BufferConfig::Valkey {
                endpoint,
                credentials,
            } => {
                #[cfg(feature = "valkey")]
                {
                    let valkey = crate::valkey_buffer::ValkeyBuffer::try_new(
                        namespace.clone(),
                        endpoint.clone(),
                        credentials.clone(),
                    )?;
                    Ok(Arc::new(valkey))
                }
                #[cfg(not(feature = "valkey"))]
                {
                    let _ = (endpoint, credentials, namespace);
                    Err(ConfigurationError::InvalidEndpoint {
                        reason: "valkey feature is not enabled",
                    })
                }
            }
        }
    }

    fn resolve_queue(&self) -> Result<Option<Arc<dyn WriteQueue>>, ConfigurationError> {
        let Some(config) = &self.queue_config else {
            return Ok(None);
        };
        match &config.inner {
            QueueConfigKind::Custom(queue) => Ok(Some(Arc::clone(queue))),
            QueueConfigKind::Sqs { .. } => {
                #[cfg(feature = "sqs")]
                {
                    let sqs = crate::sqs_queue::SqsQueue::try_new(config.clone())?;
                    Ok(Some(Arc::new(sqs)))
                }
                #[cfg(not(feature = "sqs"))]
                {
                    Err(ConfigurationError::InvalidQueueConfiguration {
                        reason: "sqs feature is not enabled",
                    })
                }
            }
        }
    }

    fn compute_effective_limits(
        &self,
        queue: Option<&dyn WriteQueue>,
    ) -> Result<SinkLimits, ConfigurationError> {
        let sink_limits = self.sink.limits();
        let max_ops = sink_limits.max_operations();
        let mut max_bytes = sink_limits
            .max_payload_bytes()
            .min(self.capacity.byte_limit());
        if let Some(q) = queue {
            max_bytes = max_bytes.min(q.limits().max_envelope_bytes());
        }
        let limits = SinkLimits::try_new(max_ops, max_bytes)?
            .with_receipt_overhead_bytes(sink_limits.receipt_overhead_bytes())
            .with_effect_expansion_factor(sink_limits.effect_expansion_factor());
        limits.validate()?;
        Ok(limits)
    }
}
