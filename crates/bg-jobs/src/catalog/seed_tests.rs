use std::{
    num::NonZeroU64,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use bytes::Bytes;

use super::{CatalogManifest, CatalogRevision, JobCatalog};
use crate::{
    ClaimedJob, FairnessPolicy, JobId, JobOutcome, JobSystem, JobSystemError, OutcomeCode,
    Timestamp,
    store::{
        CommitOutcome, JobStore, Mutation, RangePage, RangeRequest, StoreCapabilities, StoreKey,
        StoreTransaction,
    },
    test_helper::{FakeStore, FakeStoreError, block_on, low_volume_job, system, wake_scheduler},
};

fn configured_system<S: JobStore>(store: S, ids: &[u8], owner: u8) -> JobSystem<S> {
    let reference = system(FakeStore::new(), FairnessPolicy::low_volume(), owner);
    let mut catalog = JobCatalog::from_registry(reference.registry().clone());
    for id in ids {
        catalog
            .add_seed_raw(low_volume_job(*id, Timestamp::ZERO))
            .unwrap();
    }
    let manifest = CatalogManifest::try_new(
        CatalogRevision::from(NonZeroU64::MIN),
        ids.iter().map(|id| JobId::from([*id; 16])).collect(),
        Vec::new(),
    )
    .unwrap();
    JobSystem::new(
        store,
        catalog.with_manifest(manifest),
        reference.namespace().clone(),
        *reference.owner(),
        wake_scheduler(),
    )
}

fn completed() -> JobOutcome {
    JobOutcome::Complete(OutcomeCode::try_new("done").unwrap())
}

fn assert_no_completion_receipts(store: &FakeStore, engine: &JobSystem<FakeStore>, ids: &[u8]) {
    for id in ids {
        assert!(
            !store
                .contains(
                    &crate::keys::operation_key(engine.namespace(), &JobId::from([*id; 16]))
                        .unwrap()
                )
                .unwrap()
        );
    }
}

#[test]
fn given_completed_configured_seed_without_a_receipt_when_restarted_then_bounded_catalog_progress_suppresses_it()
 {
    let store = FakeStore::new();
    let engine = configured_system(store.clone(), &[1], 1);
    block_on(engine.ensure_seeds(Timestamp::ZERO)).unwrap();
    let claim = block_on(engine.claim(JobId::from([1; 16]), Timestamp::ZERO)).unwrap();
    block_on(engine.complete(claim, completed(), Timestamp::ZERO)).unwrap();
    assert_no_completion_receipts(&store, &engine, &[1]);
    let before = store.snapshot().unwrap();
    let replacement = configured_system(store.clone(), &[1], 2);
    let results = block_on(replacement.ensure_seeds(Timestamp::from_millis(20))).unwrap();
    assert_eq!(
        results[0].disposition,
        crate::EnqueueDisposition::AlreadyPresent
    );
    assert_eq!(
        store.snapshot().unwrap(),
        before,
        "restart must not recreate work or mutate progress"
    );
    assert!(matches!(
        block_on(replacement.claim(JobId::from([1; 16]), Timestamp::from_millis(20))),
        Err(JobSystemError::NotFound)
    ));
}

enum Interference {
    Complete(Box<ClaimedJob>),
    AdoptSeed,
    ChangeWakeAndRegressCatalog,
}

#[derive(Clone)]
struct CatalogRaceStore {
    inner: FakeStore,
    competing: Arc<JobSystem<FakeStore>>,
    interference: Arc<Mutex<Option<Interference>>>,
    target: StoreKey,
    stale_catalog_reads: Arc<AtomicUsize>,
}

impl JobStore for CatalogRaceStore {
    type Error = FakeStoreError;
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, key: StoreKey) -> Result<Option<Bytes>, Self::Error> {
        let catalog = crate::codec::KeyCodec::encode(
            self.competing.namespace(),
            crate::codec::KeyTag::Catalog,
            &[],
        )
        .unwrap();
        if key == catalog
            && self
                .stale_catalog_reads
                .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                    value.checked_sub(1)
                })
                .is_ok()
        {
            return Ok(None);
        }
        self.inner.get(key).await
    }
    async fn get_many(&self, keys: &[StoreKey]) -> Result<Vec<Option<Bytes>>, Self::Error> {
        self.inner.get_many(keys).await
    }
    async fn read_range(&self, request: RangeRequest) -> Result<RangePage, Self::Error> {
        self.inner.read_range(request).await
    }
    async fn transact(&self, input: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        let is_put = input
            .mutations()
            .iter()
            .any(|item| matches!(item, Mutation::Put(key, _) if key == &self.target));
        let is_delete = input
            .mutations()
            .iter()
            .any(|item| matches!(item, Mutation::Delete(key) if key == &self.target));
        let interference = {
            let mut pending = self.interference.lock().unwrap();
            let applies = match pending.as_ref() {
                Some(Interference::ChangeWakeAndRegressCatalog) => is_put,
                Some(Interference::Complete(_) | Interference::AdoptSeed) => is_delete,
                None => false,
            };
            if applies { pending.take() } else { None }
        };
        match interference {
            Some(Interference::Complete(claim)) => {
                self.competing
                    .complete(*claim, completed(), Timestamp::ZERO)
                    .await
                    .unwrap();
            }
            Some(Interference::AdoptSeed) => {
                self.competing.ensure_seeds(Timestamp::ZERO).await.unwrap();
            }
            Some(Interference::ChangeWakeAndRegressCatalog) => {
                let key = crate::keys::wake_key(
                    self.competing.namespace(),
                    &crate::QueueName::try_new("default").unwrap(),
                )
                .unwrap();
                self.inner
                    .put_raw(key, crate::keys::wake_value(Timestamp::ZERO).unwrap())
                    .unwrap();
                self.stale_catalog_reads.store(1, Ordering::Release);
            }
            None => {}
        }
        self.inner.transact(input).await
    }
}

fn race_fixture(ids: &[u8]) -> (JobSystem<CatalogRaceStore>, CatalogRaceStore) {
    let inner = FakeStore::new();
    let competing = Arc::new(configured_system(inner.clone(), ids, 2));
    let store = CatalogRaceStore {
        target: crate::keys::job_key(competing.namespace(), &JobId::from([1; 16])).unwrap(),
        inner,
        competing,
        stale_catalog_reads: Arc::new(AtomicUsize::new(0)),
        interference: Arc::new(Mutex::new(None)),
    };
    (configured_system(store.clone(), ids, 1), store)
}

#[test]
fn given_distinct_seed_completions_when_catalog_updates_overlap_then_both_completion_bits_survive()
{
    let (engine, store) = race_fixture(&[1, 2]);
    block_on(engine.ensure_seeds(Timestamp::ZERO)).unwrap();
    let first = block_on(engine.claim(JobId::from([1; 16]), Timestamp::ZERO)).unwrap();
    let second = block_on(store.competing.claim(JobId::from([2; 16]), Timestamp::ZERO)).unwrap();
    *store.interference.lock().unwrap() = Some(Interference::Complete(Box::new(second)));
    block_on(engine.complete(first, completed(), Timestamp::ZERO)).unwrap();
    assert_no_completion_receipts(&store.inner, &store.competing, &[1, 2]);
    let before = store.inner.snapshot().unwrap();
    let results = block_on(store.competing.ensure_seeds(Timestamp::ZERO)).unwrap();
    assert!(
        results
            .iter()
            .all(|item| item.disposition == crate::EnqueueDisposition::AlreadyPresent)
    );
    assert_eq!(store.inner.snapshot().unwrap(), before);
}

#[test]
fn given_uninitialized_catalog_when_live_job_is_adopted_during_completion_then_recovery_adds_its_completion_mark()
 {
    let (engine, store) = race_fixture(&[1]);
    block_on(engine.initialize_catalog()).unwrap();
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let claim = block_on(engine.claim(JobId::from([1; 16]), Timestamp::ZERO)).unwrap();
    *store.interference.lock().unwrap() = Some(Interference::AdoptSeed);
    block_on(engine.complete(claim, completed(), Timestamp::ZERO)).unwrap();
    assert_no_completion_receipts(&store.inner, &store.competing, &[1]);
    let before = store.inner.snapshot().unwrap();
    let results = block_on(store.competing.ensure_seeds(Timestamp::ZERO)).unwrap();
    assert_eq!(
        results[0].disposition,
        crate::EnqueueDisposition::AlreadyPresent
    );
    assert_eq!(store.inner.snapshot().unwrap(), before);
}

#[test]
fn given_accepted_seed_with_a_stale_missing_catalog_read_when_producer_is_lost_then_replacement_preserves_and_finishes_work()
 {
    let (engine, store) = race_fixture(&[1]);
    *store.interference.lock().unwrap() = Some(Interference::ChangeWakeAndRegressCatalog);
    assert!(matches!(
        block_on(engine.ensure_seeds(Timestamp::ZERO)),
        Err(JobSystemError::UnknownCommit)
    ));
    drop(engine);
    assert_eq!(
        block_on(store.competing.recover_commits()).unwrap(),
        1,
        "a regressing catalog observation must not retire an unfulfilled accepted enqueue"
    );
    let claim = block_on(store.competing.claim(JobId::from([1; 16]), Timestamp::ZERO)).unwrap();
    assert_eq!(claim.payload(), &low_volume_job(1, Timestamp::ZERO).payload);
}

#[test]
fn given_completed_configured_seed_when_its_definition_changes_then_catalog_rejects_without_writes()
{
    let store = FakeStore::distributed();
    let original = configured_system(store.clone(), &[1], 1);
    block_on(original.ensure_seeds(Timestamp::ZERO)).unwrap();
    let claim = block_on(original.claim(JobId::from([1; 16]), Timestamp::ZERO)).unwrap();
    block_on(original.complete(claim, completed(), Timestamp::ZERO)).unwrap();
    let mut changed = low_volume_job(1, Timestamp::ZERO);
    changed.payload = Bytes::from_static(b"changed");
    let mut catalog = JobCatalog::from_registry(original.registry().clone());
    catalog.add_seed_raw(changed).unwrap();
    let manifest = CatalogManifest::try_new(
        CatalogRevision::from(NonZeroU64::MIN),
        vec![JobId::from([1; 16])],
        Vec::new(),
    )
    .unwrap();
    let replacement = JobSystem::new(
        store.clone(),
        catalog.with_manifest(manifest),
        original.namespace().clone(),
        *original.owner(),
        wake_scheduler(),
    );
    let before = store.snapshot().unwrap();
    assert!(matches!(
        block_on(replacement.ensure_seeds(Timestamp::ZERO)),
        Err(JobSystemError::JobIdConflict)
    ));
    assert_eq!(store.snapshot().unwrap(), before);
}
