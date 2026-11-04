use std::sync::atomic::Ordering;

use super::{
    codec::input_key,
    constants::{MAX_ADMISSION_ATTEMPTS, MAX_CONTROL_ATTEMPTS},
    state::{ActiveHead, Head, Phase, Slot},
};
use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError, StoreContractError, ValidationError},
    ids::LeaseToken,
    store::{CommitOutcome, JobStore, Mutation, StoreTransaction, StoreTransactionInput},
};

impl<S: JobStore> JobSystem<S> {
    pub(crate) async fn commit_durable(
        &self,
        transaction: StoreTransaction,
    ) -> JobResult<crate::store::CommitOutcome, S::Error> {
        if transaction.mutations().is_empty() {
            return self
                .store()
                .transact(&transaction)
                .await
                .map_err(JobSystemError::Store);
        }
        let token = LeaseToken::generate().map_err(|_| JobSystemError::EntropyUnavailable)?;
        let _active = self.journal.register(token)?;
        let start = self
            .journal
            .next_slot
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(transaction.operation_id().as_bytes()[0]);
        for offset in 0..MAX_ADMISSION_ATTEMPTS {
            let Some(slot) = self
                .find_available_commit_slot(start.wrapping_add(offset as u8))
                .await?
            else {
                continue;
            };
            if let Some(prepared) = self.accept_commit(&slot, &transaction, token).await? {
                return self.resume_commit(prepared, Some(transaction)).await;
            }
        }
        Err(StoreContractError::CommitCapacity.into())
    }

    async fn find_available_commit_slot(&self, index: u8) -> JobResult<Option<Slot>, S::Error> {
        if let Some(slot) = self.journal.take_reconciled()? {
            return Ok(Some(slot));
        }
        let slot = self.load_commit_slot(index).await?;
        Ok(match slot.head {
            Head::Vacant(_) => Some(slot),
            Head::Active(_) => None,
        })
    }

    async fn accept_commit(
        &self,
        previous: &Slot,
        input: &StoreTransaction,
        token: LeaseToken,
    ) -> JobResult<Option<Slot>, S::Error> {
        // Prove that an ambiguous result can transfer to durable input before
        // dispatch. Native-valid business writes alone do not prove this.
        let (pending, reservation) =
            self.build_commit_reservation(previous, input, token, Phase::Prepared)?;
        let completed = previous.replace(Head::Active(ActiveHead {
            chunks: 0,
            input_bytes: 0,
            phase: Phase::Committed,
            ..pending.active()?
        }));
        let (transaction, completed) = self.build_slot_application(previous, completed, input)?;
        match self
            .store()
            .transact(&transaction)
            .await
            .map_err(JobSystemError::Store)?
        {
            CommitOutcome::Committed => Ok(Some(completed)),
            // The exact-predecessor reservation also fences any delayed
            // atomic attempt. It recognizes that attempt's completed witness
            // instead if the atomic application already won.
            CommitOutcome::Conflict => {
                self.accept_conflicted_commit(previous, pending, reservation)
                    .await
            }
            CommitOutcome::Unknown => self.write_commit_reservation(pending, reservation).await,
        }
    }

    async fn accept_conflicted_commit(
        &self,
        previous: &Slot,
        pending: Slot,
        reservation: StoreTransaction,
    ) -> JobResult<Option<Slot>, S::Error> {
        if self.load_commit_slot(previous.index).await?.head != previous.head {
            return Ok(None);
        }
        let conflicted = pending.replace(Head::Active(ActiveHead {
            phase: Phase::Conflict,
            ..pending.active()?
        }));
        let mut draft = StoreTransactionInput::from(reservation);
        draft.replace_key(previous.check(), conflicted.encoded.clone());
        let reservation =
            self.build_transaction(draft.operation_id, draft.checks, draft.mutations)?;
        self.write_commit_reservation(conflicted, reservation).await
    }

    pub(super) async fn reserve_commit_input(
        &self,
        previous: &Slot,
        transaction: &StoreTransaction,
        token: LeaseToken,
        phase: Phase,
    ) -> JobResult<Option<Slot>, S::Error> {
        let (next, transaction) =
            self.build_commit_reservation(previous, transaction, token, phase)?;
        self.write_commit_reservation(next, transaction).await
    }

    fn build_commit_reservation(
        &self,
        previous: &Slot,
        transaction: &StoreTransaction,
        token: LeaseToken,
        phase: Phase,
    ) -> JobResult<(Slot, StoreTransaction), S::Error> {
        let capabilities = self.store().capabilities();
        let (mut head, encoded) = previous.prepare_input(transaction, token, capabilities)?;
        head.phase = phase;
        let mut mutations = self.input_mutations(previous.index, &encoded)?;
        self.remove_obsolete_input(previous, head.chunks, &mut mutations)?;
        let next = previous.replace(Head::Active(head));
        // Validate dispatch capacity before accepting recovery responsibility.
        self.build_commit_application(&next, transaction)?;
        let value = next.encoded.clone().ok_or(JobSystemError::PayloadCorrupt)?;
        mutations.push(Mutation::Put(next.key.clone(), value));
        let reservation =
            self.build_transaction(head.command_id, vec![previous.check()], mutations)?;
        Ok((next, reservation))
    }

    async fn write_commit_reservation(
        &self,
        next: Slot,
        transaction: StoreTransaction,
    ) -> JobResult<Option<Slot>, S::Error> {
        for _ in 0..MAX_CONTROL_ATTEMPTS {
            match self
                .store()
                .transact(&transaction)
                .await
                .map_err(JobSystemError::Store)?
            {
                CommitOutcome::Committed => return Ok(Some(next)),
                CommitOutcome::Conflict | CommitOutcome::Unknown => {}
            }
            let visible = self.load_commit_slot(next.index).await?;
            if next.recognizes_reservation(&visible)? {
                return Ok(Some(visible));
            }
            if next.is_proven_competing_reservation(&visible)? {
                return Ok(None);
            }
        }
        Err(JobSystemError::UnknownCommit)
    }

    fn input_mutations(
        &self,
        index: u8,
        encoded: &bytes::Bytes,
    ) -> JobResult<Vec<Mutation>, S::Error> {
        let capabilities = self.store().capabilities();
        let chunk_bytes = capabilities.max_value_bytes().get();
        let count = encoded.len().div_ceil(chunk_bytes);
        let mut mutations = Vec::with_capacity(count + 1);
        let mut keys = Vec::with_capacity(count);
        for (chunk, start) in (0..encoded.len()).step_by(chunk_bytes).enumerate() {
            let key = input_key(self.namespace(), index, chunk as u32)?;
            let end = start.saturating_add(chunk_bytes).min(encoded.len());
            mutations.push(Mutation::Put(key.clone(), encoded.slice(start..end)));
            keys.push(key);
        }
        capabilities.validate_get_many(&keys)?;
        Ok(mutations)
    }

    fn remove_obsolete_input(
        &self,
        previous: &Slot,
        retained: u32,
        mutations: &mut Vec<Mutation>,
    ) -> JobResult<(), S::Error> {
        if let Head::Active(head) = previous.head {
            for index in retained..head.chunks {
                mutations.push(Mutation::Delete(input_key(
                    self.namespace(),
                    previous.index,
                    index,
                )?));
            }
        }
        Ok(())
    }
}

impl Slot {
    fn next_generation<E>(&self) -> JobResult<u64, E> {
        let generation = match self.head {
            Head::Vacant(generation) => generation,
            Head::Active(head) => head.generation,
        };
        generation.checked_add(1).ok_or(
            ValidationError::Overflow {
                field: "commit generation",
            }
            .into(),
        )
    }

    fn recognizes_reservation<E>(&self, visible: &Self) -> JobResult<bool, E> {
        if self.head == visible.head {
            return Ok(true);
        }
        let proposed = self.active()?;
        Ok(visible.head
            == Head::Active(ActiveHead {
                phase: Phase::Committed,
                chunks: 0,
                input_bytes: 0,
                ..proposed
            }))
    }

    fn prepare_input<E>(
        &self,
        transaction: &StoreTransaction,
        token: LeaseToken,
        capabilities: crate::store::StoreCapabilities,
    ) -> JobResult<(ActiveHead, bytes::Bytes), E> {
        let encoded = transaction.encode_intent();
        let head = ActiveHead {
            generation: self.next_generation()?,
            command_id: transaction.operation_id(),
            token,
            chunks: u32::try_from(encoded.len().div_ceil(capabilities.max_value_bytes().get()))
                .map_err(|_| ValidationError::Overflow {
                    field: "commit input chunks",
                })?,
            input_bytes: u32::try_from(encoded.len()).map_err(|_| ValidationError::Overflow {
                field: "commit input bytes",
            })?,
            binding: transaction.binding(),
            phase: Phase::Prepared,
        };
        head.validate_manifest(capabilities)?;
        Ok((head, encoded))
    }
}
