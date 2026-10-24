use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};

use super::OperationId;

/// Declared durability profile for an admitted or settled write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DurabilityClass {
    Volatile,
    DiskSynced,
    RemoteValkey,
    SinkCommittedAtomic,
    SinkCommittedIdempotent,
    QueueHandedOff,
}

/// Admission outcome status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionStatus {
    Buffered,
    Written,
    Queued,
}

/// Successful write admission receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admission {
    status: AdmissionStatus,
    durability: DurabilityClass,
    operation_id: OperationId,
}

impl Admission {
    #[must_use]
    pub const fn new(
        status: AdmissionStatus,
        durability: DurabilityClass,
        operation_id: OperationId,
    ) -> Self {
        Self {
            status,
            durability,
            operation_id,
        }
    }

    #[must_use]
    pub const fn status(&self) -> AdmissionStatus {
        self.status
    }

    #[must_use]
    pub const fn durability(&self) -> DurabilityClass {
        self.durability
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn is_buffered(&self) -> bool {
        matches!(self.status, AdmissionStatus::Buffered)
    }

    #[must_use]
    pub const fn is_written(&self) -> bool {
        matches!(self.status, AdmissionStatus::Written)
    }

    #[must_use]
    pub const fn is_queued(&self) -> bool {
        matches!(self.status, AdmissionStatus::Queued)
    }
}

/// Redacted Valkey authentication and transport settings.
#[derive(Clone, PartialEq, Eq)]
pub struct ValkeyCredentials {
    username: Option<String>,
    password: String,
    require_tls: bool,
    tls_ca_pem: Option<Vec<u8>>,
}

impl ValkeyCredentials {
    #[must_use]
    pub fn new(password: impl Into<String>) -> Self {
        Self {
            username: None,
            password: password.into(),
            require_tls: true,
            tls_ca_pem: None,
        }
    }

    #[must_use]
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    #[must_use]
    pub const fn with_tls_required(mut self, require_tls: bool) -> Self {
        self.require_tls = require_tls;
        self
    }

    /// Use an explicit private CA while retaining certificate/hostname
    /// verification.
    #[must_use]
    pub fn with_tls_ca_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.tls_ca_pem = Some(pem.into());
        self
    }

    #[cfg(feature = "valkey")]
    pub(crate) fn tls_ca_pem(&self) -> Option<&[u8]> {
        self.tls_ca_pem.as_deref()
    }

    #[must_use]
    #[cfg(feature = "valkey")]
    pub(crate) fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    #[must_use]
    #[cfg(feature = "valkey")]
    pub(crate) fn password(&self) -> &str {
        &self.password
    }

    #[must_use]
    #[cfg(feature = "valkey")]
    pub(crate) const fn is_tls_required(&self) -> bool {
        self.require_tls
    }
}

impl fmt::Debug for ValkeyCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValkeyCredentials")
            .field("username_configured", &self.username.is_some())
            .field("password", &"[REDACTED]")
            .field("require_tls", &self.require_tls)
            .field("private_ca_configured", &self.tls_ca_pem.is_some())
            .finish()
    }
}

/// Retention provider selection for a writer builder.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum BufferConfig {
    #[default]
    Memory,
    Disk {
        directory: PathBuf,
    },
    Valkey {
        endpoint: String,
        credentials: ValkeyCredentials,
    },
}

impl fmt::Debug for BufferConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Memory => "Memory",
            Self::Disk { .. } => "Disk",
            Self::Valkey { .. } => "Valkey",
        })
    }
}

impl BufferConfig {
    #[must_use]
    pub const fn memory() -> Self {
        Self::Memory
    }

    #[must_use]
    pub fn disk(directory: impl Into<PathBuf>) -> Self {
        Self::Disk {
            directory: directory.into(),
        }
    }

    #[must_use]
    pub fn valkey(endpoint: impl Into<String>, credentials: ValkeyCredentials) -> Self {
        Self::Valkey {
            endpoint: endpoint.into(),
            credentials,
        }
    }
}
