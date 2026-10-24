use std::time::Duration;

pub(crate) const DEFAULT_IPC_ADDRESS: &str = "127.0.0.1:34900";
pub(crate) const DEFAULT_FLUSH_AGE_MS: u64 = 200;
pub(crate) const DEFAULT_DESTINATION_DELAY_MS: u64 = 0;
pub(crate) const DEMO_NAMESPACE: &str = "example/lambda-maximum/v1";
pub(crate) const IPC_TIMEOUT: Duration = Duration::from_secs(2);
