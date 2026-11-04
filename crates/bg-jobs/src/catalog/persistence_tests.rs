use std::{
    num::NonZeroU64,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct CommitCounter(AtomicUsize);

impl crate::observer::JobObserver for CommitCounter {
    fn observe(&self, event: crate::observer::JobEvent) {
        if matches!(
            event,
            crate::observer::JobEvent::StoreOperation {
                operation: crate::observer::StoreOperation::Commit
            }
        ) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}

use super::{CatalogManifest, CatalogRevision, JobCatalog};
use crate::{
    JobId, JobSystem, JobSystemError, Namespace, OwnerId,
    codec::{KeyCodec, KeyTag},
    test_helper::{FakeStore, block_on, wake_scheduler},
};

fn configured_system(store: FakeStore, revision: u64, ids: &[u8]) -> JobSystem<FakeStore> {
    let manifest = CatalogManifest::try_new(
        CatalogRevision::from(NonZeroU64::new(revision).unwrap()),
        ids.iter().map(|id| JobId::from([*id; 16])).collect(),
        Vec::new(),
    )
    .unwrap();
    JobSystem::new(
        store,
        JobCatalog::new().with_manifest(manifest),
        Namespace::try_new(b"configured").unwrap(),
        OwnerId::from([1; 16]),
        wake_scheduler(),
    )
}

#[test]
fn given_shared_manifest_when_another_worker_initializes_then_it_performs_no_durable_mutation() {
    let store = FakeStore::new();
    let first = configured_system(store.clone(), 1, &[1, 2]);
    let counter = Arc::new(CommitCounter(AtomicUsize::new(0)));
    let second = configured_system(store.clone(), 1, &[2, 1]).with_observer(counter.clone());
    block_on(first.initialize_catalog()).unwrap();
    let before = store.snapshot().unwrap();
    block_on(second.initialize_catalog()).unwrap();
    assert_eq!(store.snapshot().unwrap(), before);
    assert_eq!(counter.0.load(Ordering::Relaxed), 0);
}

#[test]
fn given_current_catalog_when_stale_or_inconsistent_workers_initialize_then_they_cannot_replace_it()
{
    let store = FakeStore::new();
    block_on(configured_system(store.clone(), 2, &[1, 2]).initialize_catalog()).unwrap();
    let before = store.snapshot().unwrap();
    for (revision, ids) in [(1, vec![1, 2]), (2, vec![1])] {
        assert!(matches!(
            block_on(configured_system(store.clone(), revision, &ids).initialize_catalog()),
            Err(JobSystemError::CatalogConflict)
        ));
        assert_eq!(store.snapshot().unwrap(), before);
    }
    block_on(configured_system(store.clone(), 3, &[2, 3]).initialize_catalog()).unwrap();
    assert!(matches!(
        block_on(configured_system(store, 2, &[1, 2]).initialize_catalog()),
        Err(JobSystemError::CatalogConflict)
    ));
}

#[test]
fn given_corrupt_catalog_when_initializing_then_existing_evidence_is_preserved() {
    let store = FakeStore::new();
    let engine = configured_system(store.clone(), 1, &[1]);
    let key = KeyCodec::encode(engine.namespace(), KeyTag::Catalog, &[]).unwrap();
    store
        .put_raw(key, bytes::Bytes::from_static(&[0xff]))
        .unwrap();
    let before = store.snapshot().unwrap();
    assert!(matches!(
        block_on(engine.initialize_catalog()),
        Err(JobSystemError::StoreData(_))
    ));
    assert_eq!(store.snapshot().unwrap(), before);
}

#[test]
fn given_manifest_that_cannot_hold_future_progress_when_initializing_then_capacity_is_rejected_before_any_write()
 {
    let store = FakeStore::new();
    let reference = configured_system(store.clone(), 1, &[]);
    let count = store.capabilities().max_value_bytes().get()
        / super::constants::MAX_SEED_PROGRESS_BYTES
        + 1;
    let ids = (0..count)
        .map(|index| {
            let mut id = [0; 16];
            id[..8].copy_from_slice(&(index as u64).to_be_bytes());
            JobId::from(id)
        })
        .collect();
    let manifest =
        CatalogManifest::try_new(CatalogRevision::from(NonZeroU64::MIN), ids, Vec::new()).unwrap();
    let engine = JobSystem::new(
        store.clone(),
        JobCatalog::new().with_manifest(manifest),
        reference.namespace().clone(),
        *reference.owner(),
        wake_scheduler(),
    );
    assert!(matches!(
        block_on(engine.initialize_catalog()),
        Err(JobSystemError::StoreContract(
            crate::StoreContractError::CapabilityExceeded("catalog bytes")
        ))
    ));
    assert!(store.snapshot().unwrap().is_empty());
}
