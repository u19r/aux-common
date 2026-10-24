use std::time::Duration;

use buffered_writes::{
    BufferCapacity, BufferConfig, Clock, ConfigurationError, DeliveryPolicy, FlushPolicy,
    QueueConfig, WriteObserver, WritesBuilder,
};

use super::{
    BufferedMetering, MeteringMetricsObserver, RequestMeasurement,
    metering_runtime::MeteringRuntime,
};

/// Configuration of metering defaults without exposing buffer ownership or
/// retry internals.
pub struct MeteringBuilder {
    pub(super) writer: WritesBuilder<RequestMeasurement>,
    pub(super) uses_default_observer: bool,
}

impl MeteringBuilder {
    pub fn buffer(mut self, config: BufferConfig) -> Self {
        self.writer = self.writer.buffer(config);
        self
    }
    pub fn buffer_capacity(mut self, capacity: BufferCapacity) -> Self {
        self.writer = self.writer.buffer_capacity(capacity);
        self
    }
    pub fn flush_policy(mut self, policy: impl FlushPolicy + 'static) -> Self {
        self.writer = self.writer.flush_policy(policy);
        self
    }
    pub fn periodic_flush(mut self, interval: Duration) -> Self {
        self.writer = self.writer.periodic_flush(interval);
        self
    }
    pub fn fallback(mut self, queue: QueueConfig) -> Self {
        self.writer = self.writer.fallback(queue);
        self
    }
    pub fn delivery_policy(mut self, policy: DeliveryPolicy) -> Self {
        self.writer = self.writer.delivery_policy(policy);
        self
    }
    pub fn allow_queue_success(mut self, allow: bool) -> Self {
        self.writer = self.writer.allow_queue_success(allow);
        self
    }
    pub fn with_clock(mut self, clock: impl Clock) -> Self {
        self.writer = self.writer.with_clock(clock);
        self
    }
    /// Replace the default metering metrics observer. Use one observer per
    /// writer when manually composing `MeteringMetricsObserver` with another
    /// observation destination.
    pub fn with_observer(mut self, observer: impl WriteObserver) -> Self {
        self.writer = self.writer.with_observer(observer);
        self.uses_default_observer = false;
        self
    }
    pub fn build(self) -> Result<BufferedMetering, ConfigurationError> {
        Ok(BufferedMetering {
            runtime: MeteringRuntime::Local(self.build_writer()?),
        })
    }

    /// Build the extension-owned writer without exposing its local submission
    /// authority to the function process. No IPC task starts until `serve`.
    ///
    /// ```no_run
    /// # #[cfg(feature = "buffered-lambda")]
    /// # async fn configure(
    /// #     sink: impl metrics_facade::WriteSink<metrics_facade::RequestMeasurement>,
    /// #     ipc: metrics_facade::LambdaIpcConfig,
    /// # ) -> Result<(), metrics_facade::MeteringSetupError> {
    /// let server = metrics_facade::BufferedMetering::builder("requests/v1", sink)
    ///     .build_extension(ipc)
    ///     .await?;
    /// // The trusted extension loop owns provider events, serve and shutdown.
    /// # let _ = server;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "buffered-lambda")]
    pub async fn build_extension(
        self,
        config: buffered_writes::LambdaIpcConfig,
    ) -> Result<buffered_writes::LambdaExtensionServer<RequestMeasurement>, super::MeteringSetupError>
    {
        Ok(buffered_writes::LambdaExtensionServer::bind(self.build_writer()?, config).await?)
    }

    fn build_writer(
        self,
    ) -> Result<buffered_writes::BufferedWrites<RequestMeasurement>, ConfigurationError> {
        let builder = if self.uses_default_observer {
            self.writer
                .with_observer(MeteringMetricsObserver::default())
        } else {
            self.writer
        };
        builder.build()
    }
}
