use sha2::{Digest as _, Sha256};

use super::{PreparedPayload, SealedBatch};
use crate::constants::BATCH_DIGEST_DOMAIN;

impl SealedBatch {
    /// Hash a canonical, length-delimited encoding independent of JSON
    /// formatting.
    #[must_use]
    pub fn calculate_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(BATCH_DIGEST_DOMAIN);
        hasher.update(self.batch_id().as_uuid().as_bytes());
        hasher.update(self.first_item_time_ms().to_le_bytes());
        for header in [
            self.namespace().as_str(),
            self.scope().as_str(),
            self.codec_version(),
            self.strategy_version(),
        ] {
            update_field(&mut hasher, header.as_bytes());
        }
        hasher.update((self.records().len() as u64).to_le_bytes());
        for record in self.records() {
            hasher.update(record.admitted_at_utc_ms.to_le_bytes());
            update_field(&mut hasher, record.operation_id.as_str().as_bytes());
            update_field(&mut hasher, &record.payload);
        }
        hasher.update((self.operation_ids().len() as u64).to_le_bytes());
        for id in self.operation_ids() {
            update_field(&mut hasher, id.as_str().as_bytes());
        }
        match self.prepared() {
            PreparedPayload::SharedRecords => hasher.update([0]),
            PreparedPayload::CustomOperations(operations) => {
                hasher.update([1]);
                hasher.update((operations.len() as u64).to_le_bytes());
                for operation in operations.iter() {
                    update_field(&mut hasher, operation.operation_id.as_str().as_bytes());
                    update_field(&mut hasher, &operation.payload);
                }
            }
        }
        hasher.finalize().into()
    }
}

fn update_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}
