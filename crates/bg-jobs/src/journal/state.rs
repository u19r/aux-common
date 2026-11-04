use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Mutex, atomic::AtomicU8},
};

use bytes::Bytes;

use crate::{
    error::{StoreContractError, StoreDataError},
    ids::{CommitOperationId, LeaseToken},
    store::StoreKey,
};

#[derive(Default)]
pub(crate) struct CommitJournal {
    pub(super) next_slot: AtomicU8,
    pub(super) active: Mutex<BTreeSet<LeaseToken>>,
    reconciled: Mutex<BTreeMap<u8, Slot>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Prepared,
    Committed,
    Conflict,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ActiveHead {
    pub(super) generation: u64,
    pub(super) command_id: CommitOperationId,
    pub(super) token: LeaseToken,
    pub(super) chunks: u32,
    pub(super) input_bytes: u32,
    pub(super) binding: [u8; 32],
    pub(super) phase: Phase,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Head {
    Vacant(u64),
    Active(ActiveHead),
}

#[derive(Clone)]
pub(super) struct Slot {
    pub(super) index: u8,
    pub(super) key: StoreKey,
    pub(super) encoded: Option<Bytes>,
    pub(super) head: Head,
}

impl Slot {
    pub(super) fn active(&self) -> Result<ActiveHead, StoreDataError> {
        match self.head {
            Head::Active(head) => Ok(head),
            Head::Vacant(_) => Err(StoreDataError::Malformed("vacant command slot")),
        }
    }

    pub(super) fn replace(&self, head: Head) -> Self {
        Self {
            index: self.index,
            key: self.key.clone(),
            encoded: Some(head.encode()),
            head,
        }
    }
}

pub(super) struct ActiveCommand<'a> {
    journal: &'a CommitJournal,
    token: LeaseToken,
}

impl CommitJournal {
    pub(super) fn acknowledge(&self, slot: &Slot) -> Result<(), StoreContractError> {
        self.reconciled
            .lock()
            .map_err(|_| StoreContractError::CommitJournalUnavailable)?
            .insert(slot.index, slot.clone());
        Ok(())
    }

    pub(super) fn take_reconciled(&self) -> Result<Option<Slot>, StoreContractError> {
        Ok(self
            .reconciled
            .lock()
            .map_err(|_| StoreContractError::CommitJournalUnavailable)?
            .pop_first()
            .map(|(_, slot)| slot))
    }

    pub(super) fn is_reconciled(&self, slot: &Slot) -> Result<bool, StoreContractError> {
        Ok(self
            .reconciled
            .lock()
            .map_err(|_| StoreContractError::CommitJournalUnavailable)?
            .get(&slot.index)
            .is_some_and(|known| known.head == slot.head))
    }

    pub(super) fn register(
        &self,
        token: LeaseToken,
    ) -> Result<ActiveCommand<'_>, StoreContractError> {
        self.active
            .lock()
            .map_err(|_| StoreContractError::CommitJournalUnavailable)?
            .insert(token);
        Ok(ActiveCommand {
            journal: self,
            token,
        })
    }

    pub(super) fn is_active(&self, token: LeaseToken) -> Result<bool, StoreContractError> {
        Ok(self
            .active
            .lock()
            .map_err(|_| StoreContractError::CommitJournalUnavailable)?
            .contains(&token))
    }
}

impl Drop for ActiveCommand<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.journal.active.lock() {
            active.remove(&self.token);
        }
    }
}
