use std::time::Duration;

use buffered_writes::LambdaIpcConfig;

use crate::constants::{
    DEFAULT_DESTINATION_DELAY_MS, DEFAULT_FLUSH_AGE_MS, DEFAULT_IPC_ADDRESS, IPC_TIMEOUT,
};

pub(crate) struct ExtensionConfig {
    pub(super) runtime_api: String,
    pub(super) ipc: LambdaIpcConfig,
    pub(super) flush_age: Duration,
    pub(super) destination_delay: Duration,
}

impl ExtensionConfig {
    pub(crate) fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let address = std::env::var("BUFFERED_WRITES_IPC_ADDR")
            .unwrap_or_else(|_| DEFAULT_IPC_ADDRESS.to_owned())
            .parse()
            .map_err(|_| "invalid IPC address")?;
        let token = std::env::var("BUFFERED_WRITES_IPC_TOKEN")
            .map_err(|_| "missing IPC capability token")?;
        Ok(Self {
            runtime_api: std::env::var("AWS_LAMBDA_RUNTIME_API")
                .map_err(|_| "missing Lambda Runtime API endpoint")?,
            ipc: LambdaIpcConfig::try_new(address, token)?.try_with_timeout(IPC_TIMEOUT)?,
            flush_age: Duration::from_millis(unsigned_setting(
                "BUFFERED_WRITES_FLUSH_AGE_MS",
                DEFAULT_FLUSH_AGE_MS,
            )?),
            destination_delay: Duration::from_millis(unsigned_setting(
                "BUFFERED_WRITES_DESTINATION_DELAY_MS",
                DEFAULT_DESTINATION_DELAY_MS,
            )?),
        })
    }
}

fn unsigned_setting(name: &str, default: u64) -> Result<u64, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|_| "invalid unsigned example setting".into()),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err("invalid example setting encoding".into()),
    }
}
