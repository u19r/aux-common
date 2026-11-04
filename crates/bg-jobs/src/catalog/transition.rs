use super::{
    ledger::{CatalogLedger, SeedProgress},
    persistence::CatalogSnapshot,
    transition_input::CatalogTransition,
};
use crate::{
    codec::{KeyCodec, KeyTag},
    engine::JobSystem,
    error::{JobResult, JobSystemError, StoreDataError},
    ids::Namespace,
    store::{Check, JobStore, StoreTransaction, StoreTransactionInput},
};

pub(crate) fn find_catalog_check<'a>(
    namespace: &Namespace,
    input: &'a StoreTransaction,
) -> Result<Option<&'a Check>, StoreDataError> {
    let key = KeyCodec::encode(namespace, KeyTag::Catalog, &[])?;
    Ok(input.checks().iter().find(|check| check.key() == &key))
}

impl<S: JobStore> JobSystem<S> {
    pub(crate) async fn refresh_catalog_transition(
        &self,
        input: &StoreTransaction,
        draft: &mut StoreTransactionInput,
    ) -> JobResult<bool, S::Error> {
        let Some(check) = find_catalog_check(self.namespace(), input)? else {
            return Ok(true);
        };
        let transition = CatalogTransition::from_input(self, input, check)?;
        let mut current = CatalogSnapshot::load(self).await?;
        let next = match transition.rebase_ledger(current.ledger.take())? {
            CatalogRebase::Rejected => return Ok(false),
            CatalogRebase::Apply(next) => next,
        };
        let next = next
            .map(|ledger| ledger.encode())
            .transpose()?
            .filter(|encoded| {
                current.encoded.as_ref() != Some(encoded)
                    || matches!(transition, CatalogTransition::Configure(_))
            });
        // Keep configuration intent explicit even when another producer already
        // adopted it.
        draft.replace_key(current.check(), next);
        Ok(true)
    }
}

enum CatalogRebase {
    Rejected,
    Apply(Option<CatalogLedger>),
}

impl CatalogTransition {
    fn rebase_ledger<E>(&self, current: Option<CatalogLedger>) -> JobResult<CatalogRebase, E> {
        match self {
            Self::Terminal(terminal) => {
                let mut current = current;
                if let Some(ledger) = &mut current {
                    ledger.apply_terminal_progress(terminal)?;
                }
                Ok(CatalogRebase::Apply(current))
            }
            Self::Schedule(advance) => match advance.rebase(current)? {
                Some(ledger) => Ok(CatalogRebase::Apply(Some(ledger))),
                None => Ok(CatalogRebase::Rejected),
            },
            Self::Ensure {
                job_id,
                digest,
                manifest,
            } => manifest.rebase_seed(current, *job_id, *digest),
            Self::Configure(manifest) => manifest.rebase_configuration(current),
        }
    }
}

impl super::CatalogManifest {
    fn rebase_seed<E>(
        &self,
        current: Option<CatalogLedger>,
        job_id: crate::ids::JobId,
        digest: [u8; 32],
    ) -> JobResult<CatalogRebase, E> {
        let Some(mut current) = current else {
            return Err(JobSystemError::UnknownCommit);
        };
        if current.manifest.revision() < self.revision() {
            return Err(JobSystemError::UnknownCommit);
        }
        if current.manifest.revision() == self.revision() && &current.manifest != self {
            return Err(JobSystemError::CatalogConflict);
        }
        if &current.manifest != self {
            return Ok(CatalogRebase::Rejected);
        }
        match current.seeds.get(&job_id) {
            Some(SeedProgress::Uninitialized) => {
                current.seeds.insert(job_id, SeedProgress::Pending(digest));
            }
            Some(SeedProgress::Pending(actual)) if actual == &digest => {}
            Some(SeedProgress::Pending(_) | SeedProgress::Completed(_)) => {
                return Ok(CatalogRebase::Rejected);
            }
            None => return Err(JobSystemError::PayloadCorrupt),
        }
        Ok(CatalogRebase::Apply(Some(current)))
    }

    fn rebase_configuration<E>(
        &self,
        current: Option<CatalogLedger>,
    ) -> JobResult<CatalogRebase, E> {
        if let Some(current) = &current {
            if current.manifest.revision() > self.revision() {
                return Ok(CatalogRebase::Rejected);
            }
            if current.manifest.revision() == self.revision() && &current.manifest != self {
                return Err(JobSystemError::CatalogConflict);
            }
        }
        Ok(CatalogRebase::Apply(Some(CatalogLedger::adopt_manifest(
            current, self,
        ))))
    }
}
