use std::{fmt, sync::Arc, time::SystemTime};

use zeroize::Zeroizing;

#[derive(Clone)]
pub struct AwsStaticCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

#[derive(Clone)]
pub struct AwsResolvedCredentials {
    pub credentials: AwsStaticCredentials,
    pub expires_after: Option<SystemTime>,
    pub refresh_after: Option<SystemTime>,
}

impl AwsResolvedCredentials {
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        self.needs_refresh_at(SystemTime::now())
    }

    #[must_use]
    pub fn needs_refresh_at(&self, now: SystemTime) -> bool {
        self.refresh_after
            .is_some_and(|refresh_after| now >= refresh_after)
    }
}

#[derive(Clone)]
pub enum CredentialSource {
    DefaultChain,
    Static(AwsStaticCredentials),
}

impl fmt::Debug for AwsStaticCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsStaticCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl fmt::Debug for AwsResolvedCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsResolvedCredentials")
            .field("credentials", &self.credentials)
            .field("expires_after", &self.expires_after)
            .field("refresh_after", &self.refresh_after)
            .finish()
    }
}

impl fmt::Debug for CredentialSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultChain => formatter.write_str("DefaultChain"),
            Self::Static(credentials) => {
                formatter.debug_tuple("Static").field(credentials).finish()
            }
        }
    }
}

/// Shared credential material with an optional absolute expiration time.
/// Debug output omits secret and session-token contents.
#[derive(Clone)]
pub struct Credentials {
    material: Arc<CredentialMaterial>,
    expires_after: Option<SystemTime>,
}

impl Credentials {
    #[must_use]
    pub fn new(material: AwsStaticCredentials, expires_after: Option<SystemTime>) -> Self {
        Self {
            material: Arc::new(CredentialMaterial {
                access_key_id: Zeroizing::new(material.access_key_id),
                secret_access_key: Zeroizing::new(material.secret_access_key),
                session_token: Zeroizing::new(material.session_token),
            }),
            expires_after,
        }
    }

    #[must_use]
    pub fn access_key_id(&self) -> &str {
        &self.material.access_key_id
    }

    #[must_use]
    pub fn secret_access_key(&self) -> &str {
        &self.material.secret_access_key
    }

    #[must_use]
    pub fn session_token(&self) -> Option<&str> {
        self.material.session_token.as_deref()
    }

    #[must_use]
    pub const fn expiry(&self) -> Option<SystemTime> {
        self.expires_after
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credentials")
            .field("material", &"[REDACTED]")
            .field("expires_after", &self.expires_after)
            .finish()
    }
}

// The last shared owner wipes credential strings before their allocations are
// released.
struct CredentialMaterial {
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    session_token: Zeroizing<Option<String>>,
}
