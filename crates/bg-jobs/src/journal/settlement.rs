use super::{
    codec::input_key,
    state::{Head, Slot},
};
use crate::{
    engine::JobSystem,
    error::{JobResult, StoreContractError},
    store::{CommitOutcome, JobStore, Mutation},
};

impl<S: JobStore> JobSystem<S> {
    pub(super) async fn settle_commit(
        &self,
        slot: &Slot,
        outcome: CommitOutcome,
    ) -> JobResult<CommitOutcome, S::Error> {
        let head = slot.active()?;
        if !matches!(
            (head.phase, outcome),
            (super::state::Phase::Committed, CommitOutcome::Committed)
                | (super::state::Phase::Conflict, CommitOutcome::Conflict)
        ) {
            return Err(
                crate::error::StoreDataError::Malformed("unresolved command settlement").into(),
            );
        }
        if head.chunks == 0 {
            // The outcome is known and has no pending input. Replacing this
            // exact witness in the next command atomically retires it. A
            // crash before acknowledgement leaves it for recovery instead.
            self.journal.acknowledge(slot)?;
            return Ok(outcome);
        }
        let next = slot.replace(Head::Vacant(head.generation));
        let mutations = (0..head.chunks)
            .map(|index| input_key(self.namespace(), slot.index, index).map(Mutation::Delete))
            .collect::<Result<Vec<_>, _>>()?;
        if self.write_commit_control(slot, &next, mutations).await? {
            return Ok(outcome);
        }
        let current = self.load_commit_slot(slot.index).await?;
        // Within one generation, Conflict cannot become Committed. Refresh
        // transfers directly to the next Prepared generation without Vacant.
        // Exact Vacant(g) therefore preserves its established phase outcome;
        // a higher frontier proves fencing, not the old proposed rejection.
        match current.head {
            Head::Vacant(generation) if generation == head.generation => Ok(outcome),
            Head::Vacant(generation) if generation > head.generation => outcome.after_advance(),
            Head::Active(active) if active.generation > head.generation => outcome.after_advance(),
            _ => Err(StoreContractError::CommitOwnershipLost.into()),
        }
    }
}

impl CommitOutcome {
    fn after_advance<E>(self) -> JobResult<Self, E> {
        match self {
            Self::Committed => Ok(self),
            Self::Conflict | Self::Unknown => Err(StoreContractError::RetiredCommit.into()),
        }
    }
}
