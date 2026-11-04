use super::{
    ledger::{CatalogLedger, ScheduleProgress, SeedProgress},
    persistence::CatalogSnapshot,
};
use crate::{
    engine::JobSystem,
    error::{JobResult, ValidationError},
    lifecycle::TerminalEffect,
    model::JobDefinition,
    store::{JobStore, StoreTransactionInput},
};

impl<S: JobStore> JobSystem<S> {
    pub(crate) async fn prepare_catalog_terminal_transition(
        &self,
        input: &mut StoreTransactionInput,
        effect: &TerminalEffect,
    ) -> JobResult<(), S::Error> {
        let mut snapshot = CatalogSnapshot::load(self).await?;
        let mut next = None;
        if let Some(ledger) = &mut snapshot.ledger {
            ledger.apply_terminal_progress(effect)?;
            let encoded = ledger.encode()?;
            if snapshot.encoded.as_ref() != Some(&encoded) {
                next = Some(encoded);
            }
        }
        // Guard absence too: another producer can adopt this exact job
        // without changing its job bytes before this transition commits.
        input.replace_key(snapshot.check(), next);
        Ok(())
    }
}

impl CatalogLedger {
    pub(super) fn apply_terminal_progress<E>(
        &mut self,
        terminal: &TerminalEffect,
    ) -> JobResult<(), E> {
        let job_id = terminal.record().job_id;
        if terminal.kind().removes_job()
            && let Some(SeedProgress::Pending(expected)) = self.seeds.get(&job_id)
            && *expected
                == crate::codec::job_definition_digest(&JobDefinition::from(terminal.record()))?
        {
            self.seeds
                .insert(job_id, SeedProgress::Completed(*expected));
        }
        for (schedule_id, progress) in &mut self.schedules {
            let ScheduleProgress::Current { cursor, .. } = progress else {
                continue;
            };
            let matches_job = cursor.watermark().is_some_and(|intended_at| {
                crate::ids::JobId::from(
                    crate::ids::OccurrenceId::derive(schedule_id, intended_at).into_bytes(),
                ) == job_id
            });
            if cursor.is_active()
                && matches_job
                && !cursor.mark_completed(cursor.generation(), cursor.revision())
            {
                return Err(ValidationError::Overflow {
                    field: "schedule cursor revision",
                }
                .into());
            }
        }
        Ok(())
    }
}
