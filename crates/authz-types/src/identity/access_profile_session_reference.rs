use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

use super::constants::{
    ACCESS_PROFILE_SESSION_ID_PREFIX, MAX_ACCESS_PROFILE_KEY_BYTES,
    MAX_ACCESS_PROFILE_SESSION_ID_BYTES,
};

/// The immutable access-profile binding carried by OAuth protocol records and
/// signed access-token claims.
///
/// The access-profile session remains the authority ceiling. This reference
/// contains only the fields needed to revalidate the selected session and
/// prove that related OAuth records use the same profile revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccessProfileSessionReference {
    session_id: String,
    profile_key: String,
    revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AccessProfileSessionReferenceError {
    #[error("access-profile session id is required")]
    SessionIdRequired,
    #[error("access-profile session id is invalid")]
    SessionIdInvalid,
    #[error("access-profile session id is too long")]
    SessionIdTooLong,
    #[error("access-profile profile key is required")]
    ProfileKeyRequired,
    #[error("access-profile profile key is invalid")]
    ProfileKeyInvalid,
    #[error("access-profile profile key is too long")]
    ProfileKeyTooLong,
    #[error("access-profile session revision must be positive")]
    RevisionInvalid,
    #[error("access-profile session reference fields must be present together")]
    Partial,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessProfileSessionReferenceWire {
    session_id: Option<String>,
    profile_key: Option<String>,
    revision: Option<u64>,
}

impl AccessProfileSessionReference {
    pub fn try_new(
        session_id: impl Into<String>,
        profile_key: impl Into<String>,
        revision: u64,
    ) -> Result<Self, AccessProfileSessionReferenceError> {
        let session_id = session_id.into();
        validate_session_id(&session_id)?;

        let profile_key = profile_key.into();
        validate_profile_key(&profile_key)?;

        if revision == 0 {
            return Err(AccessProfileSessionReferenceError::RevisionInvalid);
        }

        Ok(Self {
            session_id,
            profile_key,
            revision,
        })
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn profile_key(&self) -> &str {
        &self.profile_key
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

impl<'de> Deserialize<'de> for AccessProfileSessionReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let wire = AccessProfileSessionReferenceWire::deserialize(deserializer)?;
        match (wire.session_id, wire.profile_key, wire.revision) {
            (Some(session_id), Some(profile_key), Some(revision)) => {
                Self::try_new(session_id, profile_key, revision)
                    .map_err(|error| D::Error::custom(error.to_string()))
            }
            _ => Err(D::Error::custom(
                AccessProfileSessionReferenceError::Partial.to_string(),
            )),
        }
    }
}

fn validate_session_id(value: &str) -> Result<(), AccessProfileSessionReferenceError> {
    if value.is_empty() {
        return Err(AccessProfileSessionReferenceError::SessionIdRequired);
    }
    if value.len() > MAX_ACCESS_PROFILE_SESSION_ID_BYTES {
        return Err(AccessProfileSessionReferenceError::SessionIdTooLong);
    }

    let Some(uuid) = value.strip_prefix(ACCESS_PROFILE_SESSION_ID_PREFIX) else {
        return Err(AccessProfileSessionReferenceError::SessionIdInvalid);
    };
    if uuid.len() != 36
        || uuid.bytes().enumerate().any(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23) && byte != b'-'
                || !matches!(index, 8 | 13 | 18 | 23) && !byte.is_ascii_hexdigit()
        })
    {
        return Err(AccessProfileSessionReferenceError::SessionIdInvalid);
    }
    Ok(())
}

fn validate_profile_key(value: &str) -> Result<(), AccessProfileSessionReferenceError> {
    if value.is_empty() {
        return Err(AccessProfileSessionReferenceError::ProfileKeyRequired);
    }
    if value.len() > MAX_ACCESS_PROFILE_KEY_BYTES {
        return Err(AccessProfileSessionReferenceError::ProfileKeyTooLong);
    }
    if value.starts_with('-')
        || value.ends_with('-')
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
    {
        return Err(AccessProfileSessionReferenceError::ProfileKeyInvalid);
    }
    Ok(())
}
