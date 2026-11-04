use super::{admission::CatalogAdmission, ledger::SeedProgress, persistence::CatalogSnapshot};
use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    model::JobDefinition,
    store::{CommitOutcome, JobStore},
};

impl<S: JobStore> JobSystem<S> {
    pub(crate) async fn prepare_catalog_seed(
        &self,
        definition: &JobDefinition<'_>,
    ) -> JobResult<Option<CatalogAdmission>, S::Error> {
        let manifest = self
            .configured_catalog
            .as_ref()
            .ok_or(JobSystemError::CatalogConflict)?;
        let mut snapshot = CatalogSnapshot::load(self).await?;
        let ledger = snapshot
            .ledger
            .as_mut()
            .ok_or(JobSystemError::CatalogConflict)?;
        if &ledger.manifest != manifest {
            return Err(JobSystemError::CatalogConflict);
        }
        let digest = crate::codec::job_definition_digest(definition)?;
        let next = match ledger.seeds.get(&definition.job_id) {
            Some(SeedProgress::Uninitialized) => {
                ledger
                    .seeds
                    .insert(definition.job_id, SeedProgress::Pending(digest));
                Some(ledger.encode()?)
            }
            Some(SeedProgress::Pending(actual)) if *actual == digest => None,
            Some(SeedProgress::Completed(actual)) if *actual == digest => {
                self.confirm_catalog_observation(&snapshot).await?;
                return Ok(None);
            }
            Some(SeedProgress::Pending(_) | SeedProgress::Completed(_)) => {
                return Err(JobSystemError::JobIdConflict);
            }
            None => return Err(JobSystemError::CatalogConflict),
        };
        Ok(Some(CatalogAdmission::new(snapshot, next)))
    }

    async fn confirm_catalog_observation(
        &self,
        snapshot: &CatalogSnapshot,
    ) -> JobResult<(), S::Error> {
        let transaction =
            crate::transition::checked_transaction(self, vec![snapshot.check()], Vec::new())?;
        match self
            .store()
            .transact(&transaction)
            .await
            .map_err(JobSystemError::Store)?
        {
            CommitOutcome::Committed => Ok(()),
            CommitOutcome::Conflict => Err(JobSystemError::CatalogConflict),
            CommitOutcome::Unknown => Err(JobSystemError::UnknownCommit),
        }
    }
}
