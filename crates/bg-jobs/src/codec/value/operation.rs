use bytes::Bytes;

use crate::{
    codec::value::{ValueCodec, ValueTag},
    error::StoreDataError,
    ids::{JobId, OperationId},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LiveOperationAuthority {
    job_id: JobId,
    fence_high_water: u64,
    operation_id: OperationId,
}

impl LiveOperationAuthority {
    pub(crate) const fn job_id(self) -> JobId {
        self.job_id
    }

    pub(crate) const fn fence_high_water(self) -> u64 {
        self.fence_high_water
    }

    pub(crate) const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    pub(crate) fn matches_job(self, expected: JobId) -> bool {
        self.job_id() == expected
    }
}

pub(crate) fn encode_operation_marker(
    job_id: &JobId,
    operation: &OperationId,
    fence_high_water: u64,
) -> Result<Bytes, StoreDataError> {
    let mut body = Vec::with_capacity(JobId::BYTE_LENGTH + OperationId::BYTE_LENGTH + 8);
    body.extend_from_slice(job_id.as_bytes());
    body.extend_from_slice(operation.as_bytes());
    body.extend_from_slice(&fence_high_water.to_be_bytes());
    ValueCodec::encode(ValueTag::Operation, &body)
}

pub(crate) fn decode_operation(encoded: &[u8]) -> Result<LiveOperationAuthority, StoreDataError> {
    let (tag, body) = ValueCodec::decode_body(encoded)?;
    if tag != ValueTag::Operation || body.len() != JobId::BYTE_LENGTH + OperationId::BYTE_LENGTH + 8
    {
        return Err(StoreDataError::Malformed("operation marker"));
    }
    let job_id = JobId::try_from_slice(&body[..16]).map_err(StoreDataError::from)?;
    let operation_id = OperationId::try_from_slice(&body[16..32]).map_err(StoreDataError::from)?;
    let fence_high_water = u64::from_be_bytes(
        body[32..40]
            .try_into()
            .map_err(|_| StoreDataError::Malformed("operation fence"))?,
    );
    Ok(LiveOperationAuthority {
        job_id,
        operation_id,
        fence_high_water,
    })
}
