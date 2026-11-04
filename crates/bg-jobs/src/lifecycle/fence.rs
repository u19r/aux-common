use bytes::Bytes;

use crate::{
    codec::{KeyCodec, KeyTag},
    engine::JobSystem,
    error::{JobResult, JobSystemError, StoreDataError},
    store::{Check, JobStore, Mutation},
};

/// A namespace-wide compare-and-swap authority, retained across job-ID reuse.
pub(super) struct FenceReservation {
    check: Check,
    high_water: u64,
}

impl FenceReservation {
    pub(super) async fn load<S: JobStore>(system: &JobSystem<S>) -> JobResult<Self, S::Error> {
        let counter_key = KeyCodec::encode(system.namespace(), KeyTag::Fence, &[])?;
        let counter = system
            .store()
            .get(counter_key.clone())
            .await
            .map_err(JobSystemError::Store)?;
        let (check, current) = match counter {
            Some(value) => {
                let current = decode_counter(&value)?;
                (Check::Value(counter_key, value), current)
            }
            None => (Check::Absent(counter_key), 0),
        };
        Ok(Self {
            check,
            high_water: current,
        })
    }

    pub(super) fn high_water(&self) -> u64 {
        self.high_water
    }

    pub(super) fn advance(self, next: std::num::NonZeroU64) -> (Check, Mutation) {
        let mutation = Mutation::Put(
            self.check.key().clone(),
            Bytes::copy_from_slice(&next.get().to_be_bytes()),
        );
        (self.check, mutation)
    }
}

fn decode_counter(value: &[u8]) -> Result<u64, StoreDataError> {
    let bytes = value
        .try_into()
        .map_err(|_| StoreDataError::Malformed("namespace fence"))?;
    Ok(u64::from_be_bytes(bytes))
}
