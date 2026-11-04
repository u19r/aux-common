use super::super::{
    CatalogManifest,
    ledger::{CatalogLedger, ScheduleProgress},
};
use crate::{
    error::{JobResult, JobSystemError, StoreDataError},
    ids::ScheduleId,
    store::{Check, Mutation, StoreTransaction},
};

pub(in crate::catalog) struct ScheduleAdvance {
    manifest: CatalogManifest,
    schedule_id: ScheduleId,
    expected: ScheduleProgress,
    next: ScheduleProgress,
}

impl ScheduleAdvance {
    pub(in crate::catalog) fn from_input(
        input: &StoreTransaction,
        catalog: &Check,
    ) -> Result<Option<Self>, StoreDataError> {
        let Check::Value(_, value) = catalog else {
            return Ok(None);
        };
        let Some(Mutation::Put(_, next)) = input
            .mutations()
            .iter()
            .find(|mutation| mutation.key() == catalog.key())
        else {
            return Ok(None);
        };
        let previous = CatalogLedger::decode(value)?;
        let next = CatalogLedger::decode(next)?;
        if previous.manifest != next.manifest {
            return Ok(None);
        }
        let mut advance = None;
        for (schedule_id, expected) in &previous.schedules {
            let next = next
                .schedules
                .get(schedule_id)
                .ok_or(StoreDataError::Malformed("schedule membership"))?;
            if expected == next {
                continue;
            }
            if advance.is_some() {
                return Err(StoreDataError::Malformed("multiple schedule advances"));
            }
            validate_advance(expected, next)?;
            advance = Some(Self {
                manifest: previous.manifest.clone(),
                schedule_id: *schedule_id,
                expected: expected.clone(),
                next: next.clone(),
            });
        }
        Ok(advance)
    }

    pub(in crate::catalog) fn rebase<E>(
        &self,
        current: Option<CatalogLedger>,
    ) -> JobResult<Option<CatalogLedger>, E> {
        let Some(mut current) = current else {
            return Err(JobSystemError::UnknownCommit);
        };
        if current.manifest.revision() < self.manifest.revision() {
            return Err(JobSystemError::UnknownCommit);
        }
        if current.manifest.revision() == self.manifest.revision()
            && current.manifest != self.manifest
        {
            return Err(JobSystemError::CatalogConflict);
        }
        if current.manifest != self.manifest {
            return Ok(None);
        }
        let observed = current
            .schedules
            .get(&self.schedule_id)
            .ok_or(JobSystemError::PayloadCorrupt)?;
        if observed != &self.expected {
            if is_regressing_progress(observed, &self.expected) {
                return Err(JobSystemError::UnknownCommit);
            }
            return Ok(None);
        }
        current
            .schedules
            .insert(self.schedule_id, self.next.clone());
        Ok(Some(current))
    }
}

fn validate_advance(
    previous: &ScheduleProgress,
    next: &ScheduleProgress,
) -> Result<(), StoreDataError> {
    match (previous, next) {
        (ScheduleProgress::Uninitialized, ScheduleProgress::Current { .. }) => Ok(()),
        (
            ScheduleProgress::Current {
                digest: before,
                cursor: previous,
            },
            ScheduleProgress::Current {
                digest: after,
                cursor: next,
            },
        ) if before == after
            && previous.revision().checked_add(1) == Some(next.revision())
            && (previous.generation() == next.generation()
                || previous.generation().checked_add(1) == Some(next.generation())) =>
        {
            Ok(())
        }
        _ => Err(StoreDataError::Malformed("schedule cursor advance")),
    }
}

fn is_regressing_progress(observed: &ScheduleProgress, expected: &ScheduleProgress) -> bool {
    match (observed, expected) {
        (ScheduleProgress::Uninitialized, ScheduleProgress::Current { .. }) => true,
        (
            ScheduleProgress::Current {
                cursor: observed, ..
            },
            ScheduleProgress::Current {
                cursor: expected, ..
            },
        ) => observed.revision() < expected.revision(),
        (
            ScheduleProgress::Uninitialized | ScheduleProgress::Current { .. },
            ScheduleProgress::Uninitialized,
        ) => false,
    }
}
