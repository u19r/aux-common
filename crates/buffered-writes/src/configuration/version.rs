use crate::{constants::MAX_VERSION_BYTES, error::ConfigurationError};

pub(crate) fn validate_version(version: &str) -> Result<(), ConfigurationError> {
    if version.is_empty()
        || version.len() > MAX_VERSION_BYTES
        || version.trim() != version
        || version.chars().any(char::is_control)
    {
        return Err(ConfigurationError::InvalidVersion);
    }
    Ok(())
}
