//! Bounded recovery input. The journal retains it only while a command is
//! unsettled.

use bytes::Bytes;

use super::{
    Check, CommitOperationId, EffectReceiptGroup, Mutation, StoreCapabilities, StoreKey,
    StoreTransaction, StoreTransactionInput, TransactionLimits,
    constants::TRANSACTION_BINDING_VERSION,
};
use crate::{
    error::StoreDataError,
    ids::{ExecutionId, JobId, Namespace},
};

impl StoreTransaction {
    pub(crate) fn encode_intent(&self) -> Bytes {
        let mut length = CommitOperationId::BYTE_LENGTH;
        self.visit_encoding(|bytes| length += bytes.len());
        let mut encoded = Vec::with_capacity(length);
        encoded.extend_from_slice(self.operation_id().as_bytes());
        self.visit_encoding(|bytes| encoded.extend_from_slice(bytes));
        Bytes::from(encoded)
    }

    pub(crate) fn decode_intent(
        encoded: &[u8],
        capabilities: StoreCapabilities,
    ) -> Result<Self, StoreDataError> {
        let mut reader = IntentReader {
            remaining: encoded,
            capabilities,
        };
        let operation_id =
            CommitOperationId::try_from_slice(reader.take(CommitOperationId::BYTE_LENGTH)?)?;
        let version = reader.take(1)?[0];
        if version != TRANSACTION_BINDING_VERSION {
            return Err(StoreDataError::UnknownVersion(version));
        }
        let checks = reader.read_checks()?;
        let mutations = reader.read_mutations()?;
        if !reader.remaining.is_empty() {
            return Err(StoreDataError::TrailingBytes);
        }
        let transaction = Self::try_from(StoreTransactionInput {
            operation_id,
            checks,
            mutations,
            limits: TransactionLimits {
                max_checks: capabilities.max_transaction_keys(),
                max_mutations: capabilities.max_transaction_keys(),
                max_bytes: capabilities.max_transaction_bytes(),
            },
        })
        .map_err(|_| StoreDataError::Malformed("commit intent transaction"))?;
        capabilities
            .validate_transaction(&transaction)
            .map_err(|_| StoreDataError::Malformed("commit intent capacity"))?;
        Ok(transaction)
    }
}

struct IntentReader<'a> {
    remaining: &'a [u8],
    capabilities: StoreCapabilities,
}

impl<'a> IntentReader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], StoreDataError> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(StoreDataError::Truncated)?;
        self.remaining = remaining;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32, StoreDataError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| StoreDataError::Truncated)?,
        ))
    }

    fn read_count(&mut self) -> Result<usize, StoreDataError> {
        let count = self.read_u32()? as usize;
        // Every entry needs a tag, a length, and a nonempty key. Check before
        // allocating.
        if count > self.capabilities.max_transaction_keys().get() as usize
            || count > self.remaining.len() / 6
        {
            return Err(StoreDataError::Malformed("commit intent count"));
        }
        Ok(count)
    }

    fn read_key(&mut self) -> Result<StoreKey, StoreDataError> {
        let length = self.read_u32()? as usize;
        if length > self.capabilities.max_key_bytes().get() {
            return Err(StoreDataError::Malformed("commit intent key length"));
        }
        StoreKey::try_from(self.take(length)?).map_err(Into::into)
    }

    fn read_value(&mut self) -> Result<Bytes, StoreDataError> {
        let length = self.read_u32()? as usize;
        if length > self.capabilities.max_value_bytes().get() {
            return Err(StoreDataError::Malformed("commit intent value length"));
        }
        Ok(Bytes::copy_from_slice(self.take(length)?))
    }

    fn read_checks(&mut self) -> Result<Vec<Check>, StoreDataError> {
        let count = self.read_count()?;
        let mut checks = Vec::with_capacity(count);
        for _ in 0..count {
            let tag = self.take(1)?[0];
            let key = self.read_key()?;
            checks.push(match tag {
                0 => Check::Absent(key),
                1 => Check::Value(key, self.read_value()?),
                _ => return Err(StoreDataError::Malformed("commit intent check tag")),
            });
        }
        Ok(checks)
    }

    fn read_mutations(&mut self) -> Result<Vec<Mutation>, StoreDataError> {
        let count = self.read_count()?;
        let mut mutations = Vec::with_capacity(count);
        for _ in 0..count {
            let tag = self.take(1)?[0];
            mutations.push(match tag {
                2 => {
                    let key = self.read_key()?;
                    Mutation::Put(key, self.read_value()?)
                }
                3 => Mutation::Delete(self.read_key()?),
                4 => Mutation::ClearEffectReceipts(self.read_effect_receipt_group()?),
                _ => return Err(StoreDataError::Malformed("commit intent mutation tag")),
            });
        }
        Ok(mutations)
    }

    fn read_effect_receipt_group(&mut self) -> Result<EffectReceiptGroup, StoreDataError> {
        let length = self.read_u32()? as usize;
        let namespace = Namespace::try_new(self.take(length)?)?;
        let job_id = JobId::try_from_slice(self.take(16)?)?;
        let execution_id = ExecutionId::try_from_slice(self.take(16)?)?;
        EffectReceiptGroup::new(&namespace, job_id, execution_id)
    }
}
