//! Payload validation and loading for claimed lifecycle records.

// Keep payload reads and digest validation together; identity validation
// remains in `identity`.
use bytes::Bytes;
use sha2::{Digest, Sha256};

use crate::{
    codec::{ValueCodec, ValueTag},
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    keys,
    lifecycle::identity::validate_persisted_identity,
    model::{JobRecordV1, MAX_INLINE_PAYLOAD_BYTES, PayloadManifest},
    store::JobStore,
};

pub(crate) struct PayloadScanSummary {
    pub(crate) chunk_count: usize,
    pub(crate) total_length: usize,
}

pub(crate) fn scan_payload<E, I, F>(
    manifest: &PayloadManifest,
    encoded_chunks: I,
    mut consume: F,
) -> Result<PayloadScanSummary, JobSystemError<E>>
where
    I: IntoIterator<Item = Option<Bytes>>,
    F: FnMut(&[u8]),
{
    let expected_length = expected_payload_length::<E>(manifest)?;
    let mut accumulator = PayloadAccumulator::new(expected_length);
    let expected_chunks = manifest.chunk_keys.len();
    let mut encoded_chunks = encoded_chunks.into_iter();
    for _ in 0..expected_chunks {
        let Some(encoded) = encoded_chunks.next() else {
            break;
        };
        accumulator.accept::<E, _>(encoded, &mut consume)?;
    }
    accumulator.finish(manifest, encoded_chunks)
}

fn expected_payload_length<E>(manifest: &PayloadManifest) -> Result<usize, JobSystemError<E>> {
    let expected_length = manifest.total_length as usize;
    (expected_length <= MAX_INLINE_PAYLOAD_BYTES)
        .then_some(expected_length)
        .ok_or(JobSystemError::PayloadCorrupt)
}

struct PayloadAccumulator {
    expected_length: usize,
    digest: Sha256,
    summary: PayloadScanSummary,
}

impl PayloadAccumulator {
    fn new(expected_length: usize) -> Self {
        Self {
            expected_length,
            digest: Sha256::new(),
            summary: PayloadScanSummary {
                chunk_count: 0,
                total_length: 0,
            },
        }
    }

    fn accept<E, F>(
        &mut self,
        encoded: Option<Bytes>,
        consume: &mut F,
    ) -> Result<(), JobSystemError<E>>
    where
        F: FnMut(&[u8]),
    {
        let encoded = encoded.ok_or(JobSystemError::PayloadCorrupt)?;
        let (tag, body) = ValueCodec::decode_body(&encoded)?;
        if tag != ValueTag::PayloadChunk {
            return Err(JobSystemError::PayloadCorrupt);
        }
        let total_length = self
            .summary
            .total_length
            .checked_add(body.len())
            .ok_or(JobSystemError::PayloadCorrupt)?;
        if total_length > self.expected_length || total_length > MAX_INLINE_PAYLOAD_BYTES {
            return Err(JobSystemError::PayloadCorrupt);
        }
        self.summary.total_length = total_length;
        self.digest.update(body);
        consume(body);
        self.summary.chunk_count = self
            .summary
            .chunk_count
            .checked_add(1)
            .ok_or(JobSystemError::PayloadCorrupt)?;
        Ok(())
    }

    fn finish<E, I>(
        self,
        manifest: &PayloadManifest,
        mut encoded_chunks: I,
    ) -> Result<PayloadScanSummary, JobSystemError<E>>
    where
        I: Iterator<Item = Option<Bytes>>,
    {
        let valid = self.summary.chunk_count == manifest.chunk_keys.len()
            && self.summary.total_length == self.expected_length
            && self.digest.finalize().as_slice() == manifest.digest
            && encoded_chunks.next().is_none();
        if !valid {
            return Err(JobSystemError::PayloadCorrupt);
        }
        Ok(self.summary)
    }
}
pub(super) async fn load_payload_and_cancellation<S: JobStore>(
    system: &JobSystem<S>,
    record: &JobRecordV1,
) -> JobResult<(Bytes, Option<Bytes>), S::Error> {
    validate_persisted_identity(system, record.job_id, record)?;
    let cancellation_key = keys::cancellation_key(system.namespace(), &record.job_id)?;
    let mut read_keys = record.payload.chunk_keys.clone();
    read_keys.push(cancellation_key);
    let values = system.read_many(&read_keys).await?;
    if values.len() != read_keys.len() {
        return Err(JobSystemError::PayloadCorrupt);
    }
    let mut values = values.into_iter();
    let payload = decode_payload(record, (&mut values).take(record.payload.chunk_keys.len()))?;
    let cancellation = values.next().ok_or(JobSystemError::PayloadCorrupt)?;
    if let Some(encoded) = &cancellation {
        keys::validate_empty_marker(encoded, crate::codec::ValueTag::Cancellation)?;
    }
    if values.next().is_some() {
        return Err(JobSystemError::PayloadCorrupt);
    }
    Ok((payload, cancellation))
}

pub(super) fn decode_payload<E, I>(
    record: &JobRecordV1,
    encoded_chunks: I,
) -> Result<Bytes, JobSystemError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
    I: IntoIterator<Item = Option<Bytes>>,
{
    let expected_length = record.payload.total_length as usize;
    if expected_length > crate::model::MAX_INLINE_PAYLOAD_BYTES {
        return Err(JobSystemError::PayloadCorrupt);
    }
    let mut payload = Vec::with_capacity(expected_length);
    scan_payload(&record.payload, encoded_chunks, |body| {
        payload.extend_from_slice(body);
    })?;
    Ok(Bytes::from(payload))
}
