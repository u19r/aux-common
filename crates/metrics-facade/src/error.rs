/// Extension setup preserves the writer configuration and host lifecycle
/// errors.
#[derive(Debug, thiserror::Error)]
pub enum MeteringSetupError {
    #[error("metering writer configuration failed: {0}")]
    Configuration(#[from] buffered_writes::ConfigurationError),
    #[error("metering extension setup failed: {0}")]
    Lifecycle(#[from] buffered_writes::LifecycleError),
}
