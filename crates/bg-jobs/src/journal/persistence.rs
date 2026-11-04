use bytes::Bytes;

use super::{
    codec::{input_key, slot_key},
    constants::MAX_CONTROL_ATTEMPTS,
    state::{ActiveHead, Head, Slot},
};
use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError, StoreContractError, StoreDataError},
    store::{Check, CommitOutcome, JobStore, Mutation, StoreTransaction},
};

impl<S: JobStore> JobSystem<S> {
    pub(super) async fn load_commit_slot(&self, index: u8) -> JobResult<Slot, S::Error> {
        let key = slot_key(self.namespace(), index)?;
        let encoded = self
            .store()
            .get(key.clone())
            .await
            .map_err(JobSystemError::Store)?;
        let head = encoded
            .as_deref()
            .map(Head::decode)
            .transpose()?
            .unwrap_or(Head::Vacant(0));
        Ok(Slot {
            index,
            key,
            encoded,
            head,
        })
    }

    pub(super) async fn write_commit_control(
        &self,
        previous: &Slot,
        next: &Slot,
        mut mutations: Vec<Mutation>,
    ) -> JobResult<bool, S::Error> {
        let identity = match next.head {
            Head::Active(head) => head,
            Head::Vacant(_) => previous.active()?,
        };
        let value = next.encoded.clone().ok_or(JobSystemError::PayloadCorrupt)?;
        mutations.push(Mutation::Put(next.key.clone(), value.clone()));
        let transaction =
            self.build_transaction(identity.command_id, vec![previous.check()], mutations)?;
        for _ in 0..MAX_CONTROL_ATTEMPTS {
            match self
                .store()
                .transact(&transaction)
                .await
                .map_err(JobSystemError::Store)?
            {
                CommitOutcome::Committed => return Ok(true),
                CommitOutcome::Conflict | CommitOutcome::Unknown => {}
            }
            let visible = self
                .store()
                .get(next.key.clone())
                .await
                .map_err(JobSystemError::Store)?;
            if visible.as_ref() == Some(&value) {
                return Ok(true);
            }
            if visible != previous.encoded {
                return Ok(false);
            }
        }
        Err(JobSystemError::UnknownCommit)
    }

    pub(super) async fn load_commit_input(
        &self,
        slot: &Slot,
    ) -> JobResult<StoreTransaction, S::Error> {
        let head = slot.active()?;
        let capabilities = self.store().capabilities();
        head.validate_manifest(capabilities)?;
        let keys = (0..head.chunks)
            .map(|chunk| input_key(self.namespace(), slot.index, chunk))
            .collect::<Result<Vec<_>, _>>()?;
        capabilities.validate_get_many(&keys)?;
        let values = self.read_many(&keys).await?;
        head.decode_input(values, capabilities).map_err(Into::into)
    }
}

impl Slot {
    pub(super) fn is_proven_competing_reservation(
        &self,
        visible: &Self,
    ) -> Result<bool, StoreContractError> {
        let target = self
            .active()
            .map_err(|_| StoreContractError::CommitJournalUnavailable)?;
        match visible.head {
            Head::Active(head)
                if head.generation == target.generation && head.command_id == target.command_id =>
            {
                Err(StoreContractError::CommitOwnershipLost)
            }
            Head::Active(head) if head.generation > target.generation => {
                Err(StoreContractError::RetiredCommit)
            }
            Head::Vacant(generation) if generation >= target.generation => {
                Err(StoreContractError::RetiredCommit)
            }
            Head::Active(head) if head.generation == target.generation => Ok(true),
            _ => Ok(false),
        }
    }

    pub(super) fn check(&self) -> Check {
        match &self.encoded {
            Some(value) => Check::Value(self.key.clone(), value.clone()),
            None => Check::Absent(self.key.clone()),
        }
    }
}

impl ActiveHead {
    pub(super) fn validate_manifest(
        self,
        capabilities: crate::store::StoreCapabilities,
    ) -> Result<(), StoreDataError> {
        let maximum = capabilities
            .max_transaction_bytes()
            .get()
            .saturating_add((capabilities.max_transaction_keys().get() as usize).saturating_mul(10))
            .saturating_add(25);
        let count = (self.input_bytes as usize).div_ceil(capabilities.max_value_bytes().get());
        if self.input_bytes as usize > maximum
            || self.chunks as usize != count
            || self.chunks as usize >= capabilities.max_transaction_keys().get() as usize
        {
            return Err(StoreDataError::Malformed("command input bounds"));
        }
        Ok(())
    }

    fn decode_input(
        self,
        values: Vec<Option<Bytes>>,
        capabilities: crate::store::StoreCapabilities,
    ) -> Result<StoreTransaction, StoreDataError> {
        if values.len() != self.chunks as usize {
            return Err(StoreDataError::Malformed("command input cardinality"));
        }
        let mut encoded = Vec::with_capacity(self.input_bytes as usize);
        for value in values {
            let value = value.ok_or(StoreDataError::Malformed("missing command input"))?;
            if value.is_empty()
                || encoded.len().saturating_add(value.len()) > self.input_bytes as usize
            {
                return Err(StoreDataError::Malformed("command input length"));
            }
            encoded.extend_from_slice(&value);
        }
        if encoded.len() != self.input_bytes as usize {
            return Err(StoreDataError::Truncated);
        }
        let transaction = StoreTransaction::decode_intent(&encoded, capabilities)?;
        if transaction.operation_id() != self.command_id || transaction.binding() != self.binding {
            return Err(StoreDataError::Malformed("command input binding"));
        }
        Ok(transaction)
    }
}
