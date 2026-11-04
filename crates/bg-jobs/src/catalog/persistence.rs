use bytes::Bytes;

use super::{CatalogManifest, constants::MAX_CATALOG_ATTEMPTS, ledger::CatalogLedger};
use crate::{
    codec::{KeyCodec, KeyTag},
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    store::{Check, CommitOutcome, JobStore, Mutation, StoreKey, StoreTransaction},
};

impl<S: JobStore> JobSystem<S> {
    /// Initializes or advances the complete configured namespace manifest.
    /// Equal-revision membership must agree; older workers fail closed.
    /// An unchanged observation performs no native mutation.
    pub async fn initialize_catalog(&self) -> JobResult<(), S::Error> {
        let Some(manifest) = &self.configured_catalog else {
            return Ok(());
        };
        if manifest.max_encoded_bytes()? > self.store().capabilities().max_value_bytes().get() {
            return Err(
                crate::error::StoreContractError::CapabilityExceeded("catalog bytes").into(),
            );
        }
        for _ in 0..MAX_CATALOG_ATTEMPTS {
            let snapshot = CatalogSnapshot::load(self).await?;
            let Some(transaction) = snapshot.prepare_manifest(self, manifest)? else {
                return Ok(());
            };
            match self.commit_durable(transaction).await? {
                CommitOutcome::Committed => return Ok(()),
                CommitOutcome::Conflict => {}
                CommitOutcome::Unknown => return Err(JobSystemError::UnknownCommit),
            }
        }
        Err(JobSystemError::CatalogConflict)
    }
}

pub(super) struct CatalogSnapshot {
    pub(super) key: StoreKey,
    pub(super) encoded: Option<Bytes>,
    pub(super) ledger: Option<CatalogLedger>,
}

impl CatalogSnapshot {
    pub(super) async fn load<S: JobStore>(system: &JobSystem<S>) -> JobResult<Self, S::Error> {
        let key = KeyCodec::encode(system.namespace(), KeyTag::Catalog, &[])?;
        let encoded = system
            .store()
            .get(key.clone())
            .await
            .map_err(JobSystemError::Store)?;
        let ledger = encoded.as_deref().map(CatalogLedger::decode).transpose()?;
        Ok(Self {
            key,
            encoded,
            ledger,
        })
    }

    pub(super) fn check(&self) -> Check {
        match &self.encoded {
            Some(value) => Check::Value(self.key.clone(), value.clone()),
            None => Check::Absent(self.key.clone()),
        }
    }

    fn prepare_manifest<S: JobStore>(
        self,
        system: &JobSystem<S>,
        manifest: &CatalogManifest,
    ) -> JobResult<Option<StoreTransaction>, S::Error> {
        if let Some(current) = &self.ledger {
            if current.manifest.revision() > manifest.revision() {
                return Err(JobSystemError::CatalogConflict);
            }
            if current.manifest.revision() == manifest.revision() {
                return if &current.manifest == manifest {
                    Ok(None)
                } else {
                    Err(JobSystemError::CatalogConflict)
                };
            }
        }
        let next = CatalogLedger::adopt_manifest(self.ledger, manifest).encode()?;
        let check = match self.encoded {
            Some(value) => Check::Value(self.key.clone(), value),
            None => Check::Absent(self.key.clone()),
        };
        crate::transition::checked_transaction(
            system,
            vec![check],
            vec![Mutation::Put(self.key, next)],
        )
        .map(Some)
    }
}
