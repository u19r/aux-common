//! Per-execution job effect receipt keys and their atomic range clear.

use crate::{
    codec::{KeyCodec, KeyTag},
    error::StoreDataError,
    ids::{ExecutionId, JobId, Namespace},
    store::StoreKey,
};

/// The receipt families that share one execution's group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EffectReceiptKind {
    Effect = 0,
    TerminalProjection = 1,
}

/// All effect receipts of one job execution. Every member key starts with
/// `prefix`, and every member key sorts below `end`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectReceiptGroup {
    namespace: Namespace,
    job_id: JobId,
    execution_id: ExecutionId,
    prefix: StoreKey,
    end: StoreKey,
}

impl EffectReceiptGroup {
    pub fn new(
        namespace: &Namespace,
        job_id: JobId,
        execution_id: ExecutionId,
    ) -> Result<Self, StoreDataError> {
        let prefix = KeyCodec::encode(
            namespace,
            KeyTag::EffectReceipt,
            &[
                job_id.as_bytes().as_slice(),
                execution_id.as_bytes().as_slice(),
            ],
        )?;
        let end = KeyCodec::prefix_end(&prefix)
            .ok_or(StoreDataError::Malformed("effect receipt group end"))?;
        Ok(Self {
            namespace: namespace.clone(),
            job_id,
            execution_id,
            prefix,
            end,
        })
    }

    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    pub fn prefix(&self) -> &StoreKey {
        &self.prefix
    }

    pub fn end(&self) -> &StoreKey {
        &self.end
    }

    pub fn contains(&self, key: &StoreKey) -> bool {
        key.as_bytes().starts_with(self.prefix.as_bytes())
    }

    pub fn member_key(
        &self,
        kind: EffectReceiptKind,
        digest: &[u8; 32],
    ) -> Result<StoreKey, StoreDataError> {
        member_key(
            &self.namespace,
            &self.job_id,
            &self.execution_id,
            kind,
            digest,
        )
    }
}

/// Builds a member key without building the group, for one point read.
pub(crate) fn member_key(
    namespace: &Namespace,
    job_id: &JobId,
    execution_id: &ExecutionId,
    kind: EffectReceiptKind,
    digest: &[u8; 32],
) -> Result<StoreKey, StoreDataError> {
    let mut receipt = [0u8; 33];
    receipt[0] = kind as u8;
    receipt[1..].copy_from_slice(digest);
    KeyCodec::encode(
        namespace,
        KeyTag::EffectReceipt,
        &[
            job_id.as_bytes().as_slice(),
            execution_id.as_bytes().as_slice(),
            receipt.as_slice(),
        ],
    )
}
