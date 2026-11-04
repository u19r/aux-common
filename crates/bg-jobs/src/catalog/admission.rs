use bytes::Bytes;

use super::persistence::CatalogSnapshot;
use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    store::{Check, CommitOutcome, JobStore, Mutation},
};

pub(crate) struct CatalogAdmission {
    snapshot: CatalogSnapshot,
    next: Option<Bytes>,
}

impl CatalogAdmission {
    pub(super) fn new(snapshot: CatalogSnapshot, next: Option<Bytes>) -> Self {
        Self { snapshot, next }
    }

    pub(crate) fn append(&self, checks: &mut Vec<Check>, mutations: &mut Vec<Mutation>) {
        checks.push(self.snapshot.check());
        if let Some(next) = &self.next {
            mutations.push(Mutation::Put(self.snapshot.key.clone(), next.clone()));
        }
    }

    pub(super) async fn commit<S: JobStore>(
        &self,
        system: &JobSystem<S>,
    ) -> JobResult<CommitOutcome, S::Error> {
        let mut checks = Vec::new();
        let mut mutations = Vec::new();
        self.append(&mut checks, &mut mutations);
        let transaction = crate::transition::checked_transaction(system, checks, mutations)?;
        system.commit_durable(transaction).await
    }

    pub(crate) async fn confirm_existing<S: JobStore>(
        &self,
        system: &JobSystem<S>,
        job: Check,
    ) -> JobResult<(), S::Error> {
        let mut checks = vec![job];
        let mut mutations = Vec::new();
        self.append(&mut checks, &mut mutations);
        let transaction = crate::transition::checked_transaction(system, checks, mutations)?;
        match system.commit_durable(transaction).await? {
            CommitOutcome::Committed => Ok(()),
            CommitOutcome::Conflict => Err(JobSystemError::CatalogConflict),
            CommitOutcome::Unknown => Err(JobSystemError::UnknownCommit),
        }
    }
}
