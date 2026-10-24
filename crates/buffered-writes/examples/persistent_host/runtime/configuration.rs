use std::time::Duration;

use crate::constants::{
    DEFAULT_DESTINATION_DELAY_MS, DEFAULT_SHUTDOWN_GRACE_MS, DEFAULT_WRITE_VALUE,
};

pub(crate) struct HostConfig {
    pub(super) shutdown_grace: Duration,
    pub(super) destination_delay: Duration,
    pub(super) value: u64,
}

impl HostConfig {
    pub(crate) fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            shutdown_grace: Duration::from_millis(read_setting(
                "BUFFERED_WRITES_SHUTDOWN_GRACE_MS",
                DEFAULT_SHUTDOWN_GRACE_MS,
            )?),
            destination_delay: Duration::from_millis(read_setting(
                "BUFFERED_WRITES_DESTINATION_DELAY_MS",
                DEFAULT_DESTINATION_DELAY_MS,
            )?),
            value: read_setting("BUFFERED_WRITES_EXAMPLE_VALUE", DEFAULT_WRITE_VALUE)?,
        })
    }
}

fn read_setting(key: &str, default: u64) -> Result<u64, Box<dyn std::error::Error>> {
    match std::env::var(key) {
        Ok(value) => value
            .parse()
            .map_err(|_| "invalid unsigned example setting".into()),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err("invalid example setting encoding".into()),
    }
}
