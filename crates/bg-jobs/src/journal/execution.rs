use super::{
    constants::{MAX_APPLICATION_ATTEMPTS, MAX_COMMAND_PHASES, MAX_TRANSITION_REFRESHES_PER_PASS},
    state::{Head, Phase, Slot},
};
use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError, StoreContractError},
    store::{CommitOutcome, JobStore, Mutation, StoreTransaction, StoreTransactionInput},
};

impl<S: JobStore> JobSystem<S> {
    pub(super) async fn resume_commit(
        &self,
        mut slot: Slot,
        mut input: Option<StoreTransaction>,
    ) -> JobResult<CommitOutcome, S::Error> {
        let mut refreshes = 0;
        for _ in 0..MAX_COMMAND_PHASES {
            let head = slot.active()?;
            match head.phase {
                Phase::Committed => {
                    return self.settle_commit(&slot, CommitOutcome::Committed).await;
                }
                Phase::Prepared => {
                    let transaction = self.resolve_commit_input(&slot, input.take()).await?;
                    slot = self.apply_commit_input(&slot, &transaction).await?;
                    input = Some(transaction);
                }
                Phase::Conflict => {
                    let transaction = self.resolve_commit_input(&slot, input.take()).await?;
                    let Some((next, refreshed)) = self
                        .refresh_conflicted_input(&slot, &transaction, &mut refreshes)
                        .await?
                    else {
                        return self.settle_commit(&slot, CommitOutcome::Conflict).await;
                    };
                    slot = next;
                    input = Some(refreshed);
                }
            }
        }
        Err(JobSystemError::UnknownCommit)
    }

    async fn refresh_conflicted_input(
        &self,
        slot: &Slot,
        transaction: &StoreTransaction,
        refreshes: &mut usize,
    ) -> JobResult<Option<(Slot, StoreTransaction)>, S::Error> {
        if !self.probe_transition_authority(slot, transaction).await? {
            return Ok(None);
        }
        if *refreshes >= MAX_TRANSITION_REFRESHES_PER_PASS {
            return Err(JobSystemError::UnknownCommit);
        }
        let mut draft = StoreTransactionInput::from(transaction.clone());
        if !self
            .refresh_catalog_transition(transaction, &mut draft)
            .await?
            || !self
                .refresh_deduplication_transition(transaction, &mut draft, &slot.check())
                .await?
        {
            return Ok(None);
        }
        if self.fair_settlement_check(transaction)?.is_some() {
            let effect = self
                .terminal_effect(transaction)?
                .ok_or(JobSystemError::PayloadCorrupt)?;
            self.prepare_fair_terminal_transition(&mut draft, &effect)
                .await?;
        }
        crate::transition::refresh_conflicted_wake(self, transaction, &mut draft).await?;
        let refreshed =
            crate::transition::checked_transaction(self, draft.checks, draft.mutations)?;
        let next = self
            .reserve_commit_input(slot, &refreshed, slot.active()?.token, Phase::Prepared)
            .await?
            .ok_or(StoreContractError::CommitOwnershipLost)?;
        *refreshes += 1;
        Ok(Some((next, refreshed)))
    }

    async fn probe_transition_authority(
        &self,
        slot: &Slot,
        input: &StoreTransaction,
    ) -> JobResult<bool, S::Error> {
        let wake = crate::transition::find_wake_check(self.namespace(), input)?;
        let catalog = crate::catalog::find_catalog_check(self.namespace(), input)?;
        let fairness = self.fair_settlement_check(input)?;
        let deduplication = self.deduplication_enqueue_check(input)?;
        if wake.is_none() && catalog.is_none() && fairness.is_none() && deduplication.is_none() {
            return Ok(false);
        }
        let mut checks = input
            .checks()
            .iter()
            .filter(|check| {
                wake.is_none_or(|wake| check.key() != wake.key())
                    && catalog.is_none_or(|catalog| check.key() != catalog.key())
                    && fairness.is_none_or(|fairness| check.key() != fairness.key())
                    && deduplication.is_none_or(|dedupe| check.key() != dedupe.key())
            })
            .cloned()
            .collect::<Vec<_>>();
        checks.push(slot.check());
        let probe = self.build_transaction(input.operation_id(), checks, Vec::new())?;
        match self
            .store()
            .transact(&probe)
            .await
            .map_err(JobSystemError::Store)?
        {
            CommitOutcome::Committed => Ok(true),
            CommitOutcome::Conflict => Ok(false),
            CommitOutcome::Unknown => Err(JobSystemError::UnknownCommit),
        }
    }

    async fn resolve_commit_input(
        &self,
        slot: &Slot,
        cached: Option<StoreTransaction>,
    ) -> JobResult<StoreTransaction, S::Error> {
        if let Some(transaction) = cached {
            self.validate_commit_binding(slot, &transaction)?;
            return Ok(transaction);
        }
        self.load_commit_input(slot).await
    }

    fn validate_commit_binding(
        &self,
        slot: &Slot,
        transaction: &StoreTransaction,
    ) -> JobResult<(), S::Error> {
        let head = slot.active()?;
        if head.command_id != transaction.operation_id() || head.binding != transaction.binding() {
            return Err(StoreContractError::CommitContentMismatch.into());
        }
        Ok(())
    }

    async fn apply_commit_input(
        &self,
        slot: &Slot,
        input: &StoreTransaction,
    ) -> JobResult<Slot, S::Error> {
        let (transaction, committed) = self.build_commit_application(slot, input)?;
        for _ in 0..MAX_APPLICATION_ATTEMPTS {
            match self
                .store()
                .transact(&transaction)
                .await
                .map_err(JobSystemError::Store)?
            {
                CommitOutcome::Committed => return Ok(committed),
                CommitOutcome::Conflict => return self.record_commit_conflict(slot).await,
                CommitOutcome::Unknown => {}
            }
            let visible = self.load_commit_slot(slot.index).await?;
            if visible.head != slot.head {
                return self.reconcile_commit_head(slot, visible);
            }
        }
        Err(JobSystemError::UnknownCommit)
    }

    pub(super) fn build_commit_application(
        &self,
        slot: &Slot,
        input: &StoreTransaction,
    ) -> JobResult<(StoreTransaction, Slot), S::Error> {
        let head = slot.active()?;
        let committed = slot.replace(Head::Active(super::state::ActiveHead {
            phase: Phase::Committed,
            ..head
        }));
        self.build_slot_application(slot, committed, input)
    }

    pub(super) fn build_slot_application(
        &self,
        previous: &Slot,
        committed: Slot,
        input: &StoreTransaction,
    ) -> JobResult<(StoreTransaction, Slot), S::Error> {
        let mut checks = input.checks().to_vec();
        checks.push(previous.check());
        let mut mutations = input.mutations().to_vec();
        mutations.push(Mutation::Put(
            previous.key.clone(),
            committed
                .encoded
                .clone()
                .ok_or(JobSystemError::PayloadCorrupt)?,
        ));
        let transaction = self.build_transaction(input.operation_id(), checks, mutations)?;
        Ok((transaction, committed))
    }

    async fn record_commit_conflict(&self, slot: &Slot) -> JobResult<Slot, S::Error> {
        let head = slot.active()?;
        let conflicted = slot.replace(Head::Active(super::state::ActiveHead {
            phase: Phase::Conflict,
            ..head
        }));
        if self
            .write_commit_control(slot, &conflicted, Vec::new())
            .await?
        {
            return Ok(conflicted);
        }
        self.reconcile_commit_head(slot, self.load_commit_slot(slot.index).await?)
    }

    fn reconcile_commit_head(&self, expected: &Slot, visible: Slot) -> JobResult<Slot, S::Error> {
        let original = expected.active()?;
        match visible.head {
            Head::Active(current)
                if current.generation == original.generation
                    && current.command_id == original.command_id
                    && current.token == original.token =>
            {
                Ok(visible)
            }
            Head::Vacant(generation) if generation >= original.generation => {
                Err(StoreContractError::RetiredCommit.into())
            }
            Head::Active(current) if current.generation > original.generation => {
                Err(StoreContractError::RetiredCommit.into())
            }
            _ => Err(StoreContractError::CommitOwnershipLost.into()),
        }
    }
}
