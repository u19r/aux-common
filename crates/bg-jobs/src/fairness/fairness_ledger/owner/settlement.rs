use super::{
    persistence::{decode_value, encode_value},
    state::{FairBatchItemState, FairDispatchOwner},
};
use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    keys,
    lifecycle::{TerminalEffect, TerminalEffectKind},
    model::JobState,
    store::{Check, JobStore, StoreTransaction, StoreTransactionInput},
};

impl<S: JobStore> JobSystem<S> {
    pub(crate) async fn prepare_fair_terminal_transition(
        &self,
        input: &mut StoreTransactionInput,
        terminal: &TerminalEffect,
    ) -> JobResult<(), S::Error> {
        let key = keys::fair_state_key(self.namespace())?;
        let encoded = self
            .store()
            .get(key.clone())
            .await
            .map_err(JobSystemError::Store)?;
        let mut next = None;
        if let Some(value) = &encoded {
            let mut owner = FairDispatchOwner::decode(decode_value(value)?)?;
            owner.settle_terminal_job(terminal);
            let changed = encode_value(&owner)?;
            if changed != value {
                next = Some(changed);
            }
        }
        let check = match encoded {
            Some(value) => Check::Value(key, value),
            None => Check::Absent(key),
        };
        input.replace_key(check, next);
        Ok(())
    }

    pub(crate) fn fair_settlement_check<'a>(
        &self,
        input: &'a StoreTransaction,
    ) -> JobResult<Option<&'a Check>, S::Error> {
        let key = keys::fair_state_key(self.namespace())?;
        let Some(check) = input.checks().iter().find(|check| check.key() == &key) else {
            return Ok(None);
        };
        Ok(self.terminal_effect(input)?.map(|_| check))
    }
}

impl FairDispatchOwner {
    fn settle_terminal_job(&mut self, terminal: &TerminalEffect) {
        if matches!(terminal.record().state, JobState::Leased(_)) {
            self.ledger.complete_candidate(terminal.record().job_id);
        } else {
            self.remove_candidate(terminal.record().job_id);
        }
        if self.batch.active && self.batch.members.contains(&terminal.record().job_id) {
            let result = match terminal.kind() {
                TerminalEffectKind::Completed => FairBatchItemState::Success,
                TerminalEffectKind::Cancelled
                | TerminalEffectKind::DeadLettered
                | TerminalEffectKind::Retired => FairBatchItemState::DeadLetter,
            };
            self.batch.results.insert(terminal.record().job_id, result);
        }
        self.compact_terminal_candidates();
    }
}
