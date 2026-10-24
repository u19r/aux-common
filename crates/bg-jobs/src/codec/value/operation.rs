use bytes::Bytes;

use crate::{
    codec::value::{
        ValueCodec, ValueTag,
        constants::{DEFINED_RECEIPT_KIND, MARKER_KIND, RECEIPT_KIND, WATERMARK_KIND},
        decode_effect_mode, encode_effect_mode,
    },
    error::StoreDataError,
    ids::{JobId, OperationId},
    model::{OperationReceipt, TerminalDisposition},
    policy::OutcomeCode,
    time::Timestamp,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LiveOperationAuthority {
    job_id: JobId,
    fence_high_water: u64,
    operation_id: Option<OperationId>,
}

impl LiveOperationAuthority {
    pub(crate) const fn job_id(self) -> JobId {
        self.job_id
    }

    pub(crate) const fn fence_high_water(self) -> u64 {
        self.fence_high_water
    }

    pub(crate) const fn operation_id(self) -> Option<OperationId> {
        self.operation_id
    }

    pub(crate) fn matches_job(self, expected: JobId) -> bool {
        self.job_id() == expected
    }
}

pub(crate) enum DecodedOperation {
    Live(LiveOperationAuthority),
    Receipt(OperationReceipt),
}

pub(crate) fn encode_operation_marker(
    job_id: &JobId,
    operation: &OperationId,
    fence_high_water: u64,
) -> Result<Bytes, StoreDataError> {
    let mut body = Vec::with_capacity(1 + JobId::BYTE_LENGTH + OperationId::BYTE_LENGTH + 8);
    body.push(MARKER_KIND);
    body.extend_from_slice(job_id.as_bytes());
    body.extend_from_slice(operation.as_bytes());
    body.extend_from_slice(&fence_high_water.to_be_bytes());
    ValueCodec::encode(ValueTag::Operation, &body)
}

pub(crate) fn encode_operation_watermark(
    job_id: &JobId,
    fence_high_water: u64,
) -> Result<Bytes, StoreDataError> {
    let mut body = Vec::with_capacity(1 + JobId::BYTE_LENGTH + 8);
    body.push(WATERMARK_KIND);
    body.extend_from_slice(job_id.as_bytes());
    body.extend_from_slice(&fence_high_water.to_be_bytes());
    ValueCodec::encode(ValueTag::Operation, &body)
}

pub(crate) fn encode_operation_receipt(
    receipt: &OperationReceipt,
) -> Result<Bytes, StoreDataError> {
    let mut writer = Writer::new();
    writer.u8(if receipt.definition_digest.is_some() {
        DEFINED_RECEIPT_KIND
    } else {
        RECEIPT_KIND
    });
    writer.fixed(receipt.operation_id.as_bytes());
    writer.fixed(receipt.job_id.as_bytes());
    writer.u32(receipt.generation);
    writer.u64(receipt.revision);
    writer.fixed(receipt.execution_id.as_bytes());
    writer.fixed(receipt.attempt_id.as_bytes());
    writer.u32(receipt.attempts.get());
    writer.fixed(receipt.owner.as_bytes());
    writer.fixed(receipt.token.as_bytes());
    writer.u64(receipt.fence.get());
    writer.u8(encode_effect_mode(receipt.effect_mode));
    writer.i64(receipt.created_at.as_millis());
    writer.i64(receipt.completed_at.as_millis());
    writer.u8(terminal_byte(receipt.terminal));
    writer.bytes(receipt.kind.as_str().as_bytes())?;
    writer.bytes(receipt.queue.as_str().as_bytes())?;
    writer.bytes(receipt.outcome.as_str().as_bytes())?;
    if let Some(digest) = receipt.definition_digest {
        writer.fixed(&digest);
    }
    ValueCodec::encode(ValueTag::Operation, &writer.bytes)
}

pub(crate) fn decode_operation(encoded: &[u8]) -> Result<DecodedOperation, StoreDataError> {
    let (tag, body) = ValueCodec::decode_body(encoded)?;
    if tag != ValueTag::Operation {
        return Err(StoreDataError::Malformed("operation marker"));
    }
    let kind = *body
        .first()
        .ok_or(StoreDataError::Malformed("operation kind"))?;
    match kind {
        MARKER_KIND => decode_marker(body).map(DecodedOperation::Live),
        RECEIPT_KIND | DEFINED_RECEIPT_KIND => {
            decode_receipt(&body[1..], kind).map(DecodedOperation::Receipt)
        }
        WATERMARK_KIND => decode_watermark(body).map(DecodedOperation::Live),
        _ => Err(StoreDataError::Malformed("operation kind")),
    }
}

fn decode_marker(body: &[u8]) -> Result<LiveOperationAuthority, StoreDataError> {
    if body.len() != 1 + JobId::BYTE_LENGTH + OperationId::BYTE_LENGTH + 8 {
        return Err(StoreDataError::Malformed("operation marker"));
    }
    let job_id = JobId::try_from_slice(&body[1..17]).map_err(StoreDataError::from)?;
    let operation_id = OperationId::try_from_slice(&body[17..33]).map_err(StoreDataError::from)?;
    let fence_high_water = u64::from_be_bytes(
        body[33..41]
            .try_into()
            .map_err(|_| StoreDataError::Malformed("operation fence"))?,
    );
    Ok(LiveOperationAuthority {
        job_id,
        fence_high_water,
        operation_id: Some(operation_id),
    })
}

fn decode_watermark(body: &[u8]) -> Result<LiveOperationAuthority, StoreDataError> {
    if body.len() != 1 + JobId::BYTE_LENGTH + 8 {
        return Err(StoreDataError::Malformed("operation watermark"));
    }
    let job_id = JobId::try_from_slice(&body[1..17]).map_err(StoreDataError::from)?;
    let fence_high_water = u64::from_be_bytes(
        body[17..25]
            .try_into()
            .map_err(|_| StoreDataError::Malformed("operation fence"))?,
    );
    Ok(LiveOperationAuthority {
        job_id,
        fence_high_water,
        operation_id: None,
    })
}

fn decode_receipt(body: &[u8], kind: u8) -> Result<OperationReceipt, StoreDataError> {
    let mut reader = Reader::new(body);
    let mut receipt = OperationReceipt {
        definition_digest: None,
        operation_id: reader.id("operation ID")?,
        job_id: reader.id("job ID")?,
        generation: reader.u32()?,
        revision: reader.u64()?,
        execution_id: reader.id("execution ID")?,
        attempt_id: reader.id("attempt ID")?,
        attempts: reader.non_zero_u32("attempt count")?,
        owner: reader.id("owner ID")?,
        token: reader.id("lease token")?,
        fence: reader.non_zero_u64("lease fence")?,
        effect_mode: decode_effect_mode(reader.u8()?)?,
        created_at: Timestamp::from_millis(reader.i64()?),
        completed_at: Timestamp::from_millis(reader.i64()?),
        terminal: decode_terminal(reader.u8()?)?,
        kind: reader
            .text("job kind")?
            .try_into()
            .map_err(|_| StoreDataError::Malformed("job kind"))?,
        queue: reader
            .text("queue")?
            .try_into()
            .map_err(|_| StoreDataError::Malformed("queue"))?,
        outcome: OutcomeCode::try_new(reader.text("outcome code")?)
            .map_err(StoreDataError::from)?,
    };
    if kind == DEFINED_RECEIPT_KIND {
        receipt.definition_digest = Some(
            reader
                .fixed(32)?
                .try_into()
                .map_err(|_| StoreDataError::Truncated)?,
        );
    }
    reader.finish()?;
    Ok(receipt)
}

const fn terminal_byte(terminal: TerminalDisposition) -> u8 {
    match terminal {
        TerminalDisposition::Completed => 0,
    }
}

fn decode_terminal(value: u8) -> Result<TerminalDisposition, StoreDataError> {
    match value {
        0 => Ok(TerminalDisposition::Completed),
        _ => Err(StoreDataError::Malformed("terminal disposition")),
    }
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(256),
        }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), StoreDataError> {
        let length = u32::try_from(value.len()).map_err(|_| StoreDataError::LengthOverflow)?;
        self.u32(length);
        self.fixed(value);
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn fixed(&mut self, length: usize) -> Result<&'a [u8], StoreDataError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(StoreDataError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(StoreDataError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, StoreDataError> {
        Ok(*self.fixed(1)?.first().ok_or(StoreDataError::Truncated)?)
    }

    fn u32(&mut self) -> Result<u32, StoreDataError> {
        Ok(u32::from_be_bytes(
            self.fixed(4)?
                .try_into()
                .map_err(|_| StoreDataError::Truncated)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, StoreDataError> {
        Ok(u64::from_be_bytes(
            self.fixed(8)?
                .try_into()
                .map_err(|_| StoreDataError::Truncated)?,
        ))
    }

    fn i64(&mut self) -> Result<i64, StoreDataError> {
        Ok(i64::from_be_bytes(
            self.fixed(8)?
                .try_into()
                .map_err(|_| StoreDataError::Truncated)?,
        ))
    }

    fn id<T>(&mut self, field: &'static str) -> Result<T, StoreDataError>
    where T: TryFrom<&'a [u8]> {
        T::try_from(self.fixed(16)?).map_err(|_| StoreDataError::Malformed(field))
    }

    fn non_zero_u32(
        &mut self,
        field: &'static str,
    ) -> Result<std::num::NonZeroU32, StoreDataError> {
        std::num::NonZeroU32::new(self.u32()?).ok_or(StoreDataError::Malformed(field))
    }

    fn non_zero_u64(
        &mut self,
        field: &'static str,
    ) -> Result<std::num::NonZeroU64, StoreDataError> {
        std::num::NonZeroU64::new(self.u64()?).ok_or(StoreDataError::Malformed(field))
    }

    fn text(&mut self, field: &'static str) -> Result<&'a str, StoreDataError> {
        let length = self.u32()? as usize;
        std::str::from_utf8(self.fixed(length)?).map_err(|_| StoreDataError::Malformed(field))
    }

    fn finish(self) -> Result<(), StoreDataError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(StoreDataError::TrailingBytes)
        }
    }
}
