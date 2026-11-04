use std::{
    num::NonZeroU16,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;

use super::FairDispatchOwner;
use crate::{
    batch::{AuthConfigId, BatchKey, BatchResult},
    drive::{
        FairDispatchCandidateSpec, fair_dispatch_configure, fair_dispatch_release,
        fair_dispatch_select,
    },
    fairness::{FairCandidateMetadata, FairPermit, FairScope, FairVolumeMode},
    store::{
        JobStore, Mutation, RangePage, RangeRequest, StoreCapabilities, StoreKey, StoreTransaction,
    },
    test_helper::{block_on, wake_scheduler},
    *,
};

fn system<S: JobStore>(store: S, owner: u8) -> JobSystem<S> {
    JobSystem::new(
        store,
        JobCatalog::from_registry(crate::test_helper::registry(FairnessPolicy::from(
            NonZeroU16::MIN,
        ))),
        Namespace::try_new(b"jobs").unwrap(),
        OwnerId::from([owner; 16]),
        wake_scheduler(),
    )
}

fn spec(id: u8, ordering: Option<OrderingKey>) -> FairDispatchCandidateSpec {
    FairDispatchCandidateSpec {
        job_id: JobId::from([id; 16]),
        payload: Bytes::from_static(b"work"),
        fairness: FairnessClass::from(FairnessPath::new(
            FairnessKey::try_new(b"family").unwrap(),
            Some(FairnessKey::try_new([id]).unwrap()),
        )),
        volume_mode: FairVolumeMode::Scoped,
        priority: Priority::Default,
        cost_units: NonZeroU16::MIN,
        scheduled_at: Timestamp::ZERO,
        ordering_key: ordering,
        ordering_position: u64::from(id),
        metadata: FairCandidateMetadata {
            handler_kind: JobKind::try_new("email").unwrap(),
            schema_version: NonZeroU16::MIN,
            batch_key: BatchKey::new(1),
            auth_config: AuthConfigId::new(1),
            effect_mode: EffectMode::Idempotent,
            retry_policy: crate::policy::RetryPolicy::preset(RetryPreset::Network),
            timeout: Duration::from_secs(1),
            enqueued_at: Timestamp::ZERO,
            batch_deadline: Timestamp::from_millis(10),
        },
    }
}

enum Interference {
    Complete(Box<ClaimedJob>),
    Retry(FairPermit, Box<ClaimedJob>),
}

#[derive(Clone)]
struct CompletionRaceStore {
    inner: FakeStore,
    competing: Arc<JobSystem<FakeStore>>,
    pending: Arc<Mutex<Option<Interference>>>,
}

impl JobStore for CompletionRaceStore {
    type Error = FakeStoreError;
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, key: StoreKey) -> Result<Option<Bytes>, Self::Error> {
        self.inner.get(key).await
    }
    async fn get_many(&self, keys: &[StoreKey]) -> Result<Vec<Option<Bytes>>, Self::Error> {
        self.inner.get_many(keys).await
    }
    async fn read_range(&self, request: RangeRequest) -> Result<RangePage, Self::Error> {
        self.inner.read_range(request).await
    }
    async fn transact(&self, input: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        let target =
            crate::keys::job_key(self.competing.namespace(), &JobId::from([1; 16])).unwrap();
        let action = if input
            .mutations()
            .iter()
            .any(|mutation| matches!(mutation, Mutation::Delete(key) if key == &target))
        {
            self.pending.lock().unwrap().take()
        } else {
            None
        };
        match action {
            Some(Interference::Complete(claim)) => {
                self.competing
                    .complete(*claim, crate::test_helper::completion(), Timestamp::ZERO)
                    .await
                    .unwrap();
            }
            Some(Interference::Retry(permit, claim)) => {
                let result = BatchResult {
                    attempt_id: claim.attempt_id(),
                    outcome: JobOutcome::Retry {
                        class: RetryClass::Transient,
                        not_before: Some(Timestamp::from_millis(500)),
                        code: OutcomeCode::try_new("retry").unwrap(),
                    },
                };
                fair_dispatch_release(&self.competing, permit, *claim, result, Timestamp::ZERO)
                    .await
                    .unwrap();
            }
            None => {}
        }
        self.inner.transact(input).await
    }
}

fn fixture(
    ordered: bool,
) -> (
    JobSystem<CompletionRaceStore>,
    CompletionRaceStore,
    Option<OrderingKey>,
) {
    let inner = FakeStore::distributed();
    let competing = Arc::new(system(inner.clone(), 2));
    let store = CompletionRaceStore {
        inner,
        competing,
        pending: Arc::new(Mutex::new(None)),
    };
    let engine = system(store.clone(), 1);
    let ordering = ordered.then(|| OrderingKey::try_new(b"ordered").unwrap());
    for id in 1..=3 {
        let mut candidate = spec(id, if id == 2 { None } else { ordering.clone() });
        if ordered && id == 3 {
            candidate.ordering_position = 2;
        }
        block_on(fair_dispatch_configure(&engine, candidate, Timestamp::ZERO)).unwrap();
    }
    (engine, store, ordering)
}

fn primary_scope() -> FairScope {
    FairScope::Scoped {
        primary: FairnessKey::try_new(b"family").unwrap(),
        secondary: None,
    }
}

#[test]
fn given_overlapping_terminal_or_retry_outcomes_in_one_family_when_completion_rebases_then_service_and_capacity_survive()
 {
    for retry in [false, true] {
        let (engine, store, _) = fixture(false);
        let (_, first) = block_on(fair_dispatch_select(
            &engine,
            JobId::from([1; 16]),
            Timestamp::ZERO,
        ))
        .unwrap();
        let (permit, second) = block_on(fair_dispatch_select(
            &store.competing,
            JobId::from([2; 16]),
            Timestamp::ZERO,
        ))
        .unwrap();
        let owner = block_on(FairDispatchOwner::load(&engine)).unwrap().unwrap();
        let before = owner.ledger().scope_snapshot(&primary_scope()).unwrap();
        assert_eq!(
            (
                before.in_flight,
                before.permits,
                before.rate,
                before.served_cost
            ),
            (2, 0, 1, 2)
        );
        *store.pending.lock().unwrap() = Some(if retry {
            Interference::Retry(permit, Box::new(second))
        } else {
            Interference::Complete(Box::new(second))
        });
        block_on(engine.complete(first, crate::test_helper::completion(), Timestamp::ZERO))
            .unwrap();
        let owner = block_on(FairDispatchOwner::load(&engine)).unwrap().unwrap();
        let after = owner.ledger().scope_snapshot(&primary_scope()).unwrap();
        assert_eq!(
            (
                after.in_flight,
                after.permits,
                after.rate,
                after.served_cost
            ),
            (0, 2, 3, 2)
        );
        assert!(owner.candidate_snapshot(JobId::from([1; 16])).is_none());
        if retry {
            assert_eq!(
                owner
                    .candidate_snapshot(JobId::from([2; 16]))
                    .unwrap()
                    .state,
                FairCandidateState::RetryWaiting
            );
        } else {
            assert!(owner.candidate_snapshot(JobId::from([2; 16])).is_none());
        }
        let (_, third) = block_on(fair_dispatch_select(
            &engine,
            JobId::from([3; 16]),
            Timestamp::ZERO,
        ))
        .unwrap();
        let owner = block_on(FairDispatchOwner::load(&engine)).unwrap().unwrap();
        let selected = owner.ledger().scope_snapshot(&primary_scope()).unwrap();
        assert_eq!(
            (
                selected.in_flight,
                selected.permits,
                selected.rate,
                selected.served_cost
            ),
            (1, 1, 2, 3)
        );
        block_on(engine.complete(third, crate::test_helper::completion(), Timestamp::ZERO))
            .unwrap();
    }
}

#[test]
fn given_ordered_successor_when_terminal_completions_overlap_then_the_order_advances_and_successor_can_claim()
 {
    let (engine, store, ordering) = fixture(true);
    let (_, first) = block_on(fair_dispatch_select(
        &engine,
        JobId::from([1; 16]),
        Timestamp::ZERO,
    ))
    .unwrap();
    let (_, second) = block_on(fair_dispatch_select(
        &store.competing,
        JobId::from([2; 16]),
        Timestamp::ZERO,
    ))
    .unwrap();
    assert!(
        block_on(fair_dispatch_select(
            &engine,
            JobId::from([3; 16]),
            Timestamp::ZERO
        ))
        .is_err()
    );
    *store.pending.lock().unwrap() = Some(Interference::Complete(Box::new(second)));
    block_on(engine.complete(first, crate::test_helper::completion(), Timestamp::ZERO)).unwrap();
    let owner = block_on(FairDispatchOwner::load(&engine)).unwrap().unwrap();
    let order = owner.order_snapshot(&ordering.unwrap()).unwrap();
    assert_eq!(
        (order.head, order.owner, order.in_flight),
        (2, JobId::from([1; 16]), false)
    );
    let (_, successor) = block_on(fair_dispatch_select(
        &engine,
        JobId::from([3; 16]),
        Timestamp::ZERO,
    ))
    .unwrap();
    block_on(engine.complete(successor, crate::test_helper::completion(), Timestamp::ZERO))
        .unwrap();
    let owner = block_on(FairDispatchOwner::load(&engine)).unwrap().unwrap();
    assert!(owner.candidate_ids().next().is_none());
    assert!(owner.ledger().scope_snapshot(&primary_scope()).is_none());
}
