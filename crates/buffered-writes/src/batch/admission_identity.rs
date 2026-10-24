use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::record::AdmittedRecord;
use crate::{
    configuration::{OperationId, TenantScope},
    constants::ADMISSION_DIGEST_DOMAIN,
};

/// Content identity for an operation inside its configured retention namespace.
/// Providers can persist this value and compare receipts without retaining the
/// payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AdmissionFingerprint([u8; 32]);

impl AdmissionFingerprint {
    pub(crate) fn from_stored_parts(
        id: &OperationId,
        scope: &TenantScope,
        codec: &str,
        digest: &[u8; 32],
    ) -> Self {
        let mut hash = Sha256::new();
        hash.update(ADMISSION_DIGEST_DOMAIN);
        for part in [
            id.as_str().as_bytes(),
            scope.as_str().as_bytes(),
            codec.as_bytes(),
            digest,
        ] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        Self(hash.finalize().into())
    }
}

impl AdmittedRecord {
    /// Identifies the operation ID, scope, codec version, and encoded content.
    #[must_use]
    pub fn admission_fingerprint(&self) -> AdmissionFingerprint {
        AdmissionFingerprint::from_stored_parts(
            &self.operation_id,
            &self.scope,
            &self.codec_version,
            &self.digest_record(),
        )
    }

    pub(crate) fn digest_record(&self) -> [u8; 32] {
        // Disk journal v5 stores this digest; fingerprints frame it with its
        // metadata.
        let mut hash = Sha256::new();
        hash.update(self.scope.as_str().as_bytes());
        hash.update(b":");
        hash.update(self.codec_version.as_bytes());
        hash.update(b":");
        hash.update(&self.payload);
        hash.finalize().into()
    }
}
