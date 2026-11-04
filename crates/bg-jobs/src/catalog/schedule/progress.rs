use super::super::{CatalogAdmission, ledger::ScheduleProgress, persistence::CatalogSnapshot};
use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError, StoreDataError},
    ids::ScheduleId,
    schedule::{ScheduleControl, ScheduleControlResult, ScheduleCursor},
    store::{CommitOutcome, JobStore},
};

pub(crate) struct CurrentSchedule {
    snapshot: CatalogSnapshot,
    schedule_id: ScheduleId,
    digest: [u8; 32],
    cursor: ScheduleCursor,
    initialized: bool,
}

impl<S: JobStore> JobSystem<S> {
    pub(crate) async fn load_schedule_progress(
        &self,
        schedule_id: ScheduleId,
        digest: [u8; 32],
        initial: &ScheduleCursor,
    ) -> JobResult<CurrentSchedule, S::Error> {
        let manifest = self
            .configured_catalog
            .as_ref()
            .ok_or(JobSystemError::CatalogConflict)?;
        let snapshot = CatalogSnapshot::load(self).await?;
        let ledger = snapshot
            .ledger
            .as_ref()
            .ok_or(JobSystemError::CatalogConflict)?;
        if &ledger.manifest != manifest {
            return Err(JobSystemError::CatalogConflict);
        }
        let (cursor, initialized) = match ledger.schedules.get(&schedule_id) {
            Some(ScheduleProgress::Uninitialized) if !initial.is_active() => {
                (initial.clone(), false)
            }
            Some(ScheduleProgress::Uninitialized) => {
                return Err(crate::error::ValidationError::InvalidValue {
                    field: "active initial schedule",
                }
                .into());
            }
            Some(ScheduleProgress::Current {
                digest: current,
                cursor,
            }) if current == &digest => (cursor.clone(), true),
            Some(ScheduleProgress::Current { .. }) => return Err(JobSystemError::JobIdConflict),
            None => return Err(JobSystemError::CatalogConflict),
        };
        Ok(CurrentSchedule {
            snapshot,
            schedule_id,
            digest,
            cursor,
            initialized,
        })
    }
    /// Applies version-checked control to an initialized configured schedule.
    pub async fn control_schedule(
        &self,
        schedule_id: ScheduleId,
        revision: u64,
        generation: u32,
        control: ScheduleControl,
    ) -> JobResult<ScheduleControlResult, S::Error> {
        let current = self.load_initialized_schedule(schedule_id).await?;
        let mut next = current.cursor.clone();
        let result = next.apply_control(revision, generation, control);
        if matches!(result, ScheduleControlResult::Conflict { .. }) {
            return Ok(result);
        }
        match current.persist(self, next).await {
            Ok(()) => Ok(result),
            Err(JobSystemError::CatalogConflict) => {
                let observed = self.load_initialized_schedule(schedule_id).await?;
                Ok(ScheduleControlResult::Conflict {
                    revision: observed.cursor.revision(),
                    generation: observed.cursor.generation(),
                })
            }
            Err(error) => Err(error),
        }
    }

    async fn load_initialized_schedule(
        &self,
        schedule_id: ScheduleId,
    ) -> JobResult<CurrentSchedule, S::Error> {
        let manifest = self
            .configured_catalog
            .as_ref()
            .ok_or(JobSystemError::CatalogConflict)?;
        let snapshot = CatalogSnapshot::load(self).await?;
        let ledger = snapshot
            .ledger
            .as_ref()
            .ok_or(JobSystemError::CatalogConflict)?;
        if &ledger.manifest != manifest {
            return Err(JobSystemError::CatalogConflict);
        }
        let (digest, cursor) = match ledger.schedules.get(&schedule_id) {
            Some(ScheduleProgress::Current { digest, cursor }) => (*digest, cursor.clone()),
            Some(ScheduleProgress::Uninitialized) | None => return Err(JobSystemError::NotFound),
        };
        Ok(CurrentSchedule {
            snapshot,
            schedule_id,
            digest,
            cursor,
            initialized: true,
        })
    }
}

impl CurrentSchedule {
    pub(crate) fn cursor(&self) -> &ScheduleCursor {
        &self.cursor
    }

    pub(crate) fn admission(
        mut self,
        next: ScheduleCursor,
    ) -> Result<Option<CatalogAdmission>, StoreDataError> {
        if self.initialized && self.cursor == next {
            return Ok(None);
        }
        let ledger = self
            .snapshot
            .ledger
            .as_mut()
            .ok_or(StoreDataError::Malformed("missing schedule catalog"))?;
        ledger.schedules.insert(
            self.schedule_id,
            ScheduleProgress::Current {
                digest: self.digest,
                cursor: next,
            },
        );
        let encoded = ledger.encode()?;
        Ok(Some(CatalogAdmission::new(self.snapshot, Some(encoded))))
    }

    pub(crate) async fn persist<S: JobStore>(
        self,
        system: &JobSystem<S>,
        next: ScheduleCursor,
    ) -> JobResult<(), S::Error> {
        let Some(admission) = self.admission(next)? else {
            return Ok(());
        };
        match admission.commit(system).await? {
            CommitOutcome::Committed => Ok(()),
            CommitOutcome::Conflict => Err(JobSystemError::CatalogConflict),
            CommitOutcome::Unknown => Err(JobSystemError::UnknownCommit),
        }
    }
}
