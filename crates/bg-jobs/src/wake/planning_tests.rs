use std::{
    num::{NonZeroU32, NonZeroUsize},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;

use crate::{test_helper::block_on, *};

#[test]
fn given_watermark_candidates_when_lowering_then_only_an_earlier_value_advances_revision() {
    let mut watermark = WakeWatermark::new();

    assert!(watermark.lower(Timestamp::from_millis(50)));
    assert_eq!(watermark.value(), Some(Timestamp::from_millis(50)));
    assert_eq!(watermark.revision(), 1);
    assert!(!watermark.lower(Timestamp::from_millis(75)));
    assert!(!watermark.lower(Timestamp::from_millis(50)));
    assert!(watermark.lower(Timestamp::from_millis(25)));
    assert_eq!(watermark.revision(), 2);
}

#[test]
fn given_a_stale_early_watermark_when_raising_or_clearing_then_late_work_is_never_delayed() {
    let mut watermark = WakeWatermark::from_hint(WakeHint::At(Timestamp::from_millis(10)));
    let revision = watermark.revision();

    assert!(
        !watermark.compare_and_set(revision.saturating_add(1), Some(Timestamp::from_millis(20)))
    );
    assert_eq!(watermark.value(), Some(Timestamp::from_millis(10)));
    assert!(watermark.compare_and_set(revision, Some(Timestamp::from_millis(20))));
    assert_eq!(watermark.value(), Some(Timestamp::from_millis(20)));
    assert!(watermark.raise_stale(None));
    assert_eq!(watermark.hint(), WakeHint::None);
}

#[test]
fn given_bounded_watermark_due_and_schedule_heads_when_merging_then_earliest_and_now_have_priority()
{
    let limit = NonZeroU32::new(2).expect("merge limit is non-zero");
    let candidates = WakeCandidates {
        watermarks: vec![WakeHint::At(Timestamp::from_millis(80))],
        due_heads: vec![WakeHint::At(Timestamp::from_millis(50))],
        schedule_heads: vec![WakeHint::At(Timestamp::from_millis(70))],
    };
    assert_eq!(
        candidates.merge(limit),
        WakeHint::At(Timestamp::from_millis(50))
    );
    let immediate = WakeCandidates {
        watermarks: vec![WakeHint::At(Timestamp::from_millis(80)), WakeHint::Now],
        ..WakeCandidates::default()
    };
    assert_eq!(immediate.merge(limit), WakeHint::Now);
}

#[test]
fn given_a_shared_merge_limit_when_one_source_exhausts_it_then_later_sources_are_not_scanned() {
    let candidates = WakeCandidates {
        watermarks: vec![
            WakeHint::At(Timestamp::from_millis(80)),
            WakeHint::At(Timestamp::from_millis(90)),
        ],
        due_heads: vec![WakeHint::At(Timestamp::from_millis(70))],
        schedule_heads: vec![WakeHint::At(Timestamp::from_millis(10))],
    };

    assert_eq!(
        candidates.merge(NonZeroU32::new(2).expect("merge limit is non-zero")),
        WakeHint::At(Timestamp::from_millis(80))
    );
}

#[test]
fn given_concurrent_producers_when_lowering_one_shared_watermark_then_the_earliest_candidate_survives()
 {
    let watermark = Arc::new(Mutex::new(WakeWatermark::new()));
    let mut threads = Vec::new();
    for value in [90, 30, 70, 10, 50] {
        let watermark = Arc::clone(&watermark);
        threads.push(std::thread::spawn(move || {
            let mut guard = watermark.lock().expect("watermark lock is healthy");
            guard.lower(Timestamp::from_millis(value));
        }));
    }
    for thread in threads {
        thread.join().expect("producer finishes");
    }

    assert_eq!(
        watermark.lock().expect("watermark lock is healthy").value(),
        Some(Timestamp::from_millis(10))
    );
}

#[test]
fn given_foreign_queue_entries_when_finding_target_due_then_only_the_target_page_is_read() {
    let store = RangeCountingStore::new();
    let engine = range_counting_system(store.clone());
    let foreign_queue = QueueName::try_new("aaa").expect("foreign queue is valid");
    let target_queue = QueueName::try_new("default").expect("target queue is valid");
    let foreign_include = crate::keys::due_key(
        engine.namespace(),
        &foreign_queue,
        Timestamp::from_millis(5),
        &JobId::from([0xf0; 16]),
    )
    .expect("foreign include key is valid");
    for index in 0..65_u8 {
        let mut id_bytes = [0xf0; 16];
        id_bytes[15] = index;
        let foreign_id = JobId::from(id_bytes);
        let foreign_due = Timestamp::from_millis(5 + i64::from(index));
        store.put_raw(
            crate::keys::due_key(engine.namespace(), &foreign_queue, foreign_due, &foreign_id)
                .expect("foreign due key is valid"),
            crate::keys::due_value(foreign_due).expect("foreign due value is valid"),
        );
    }

    let mut mutations = Vec::new();
    let wake_check = block_on(crate::transition::wake_mutation(
        &engine,
        &target_queue,
        None,
        Some(&foreign_include),
        &mut mutations,
    ))
    .expect("target wake reconciliation succeeds");

    assert!(wake_check.is_none());
    assert!(mutations.is_empty());
    assert_eq!(
        store.range_reads(),
        1,
        "foreign queues must not consume pages"
    );
}

#[test]
fn given_sixty_five_target_queue_pages_when_reconciling_wake_then_the_incomplete_watermark_is_preserved()
 {
    let store = RangeCountingStore::new();
    let engine = range_counting_system(store.clone());
    let target_queue = QueueName::try_new("default").expect("target queue is valid");
    for index in 0..65_u8 {
        let mut id_bytes = [0xf0; 16];
        id_bytes[15] = index;
        let target_id = JobId::from(id_bytes);
        let target_due = Timestamp::from_millis(100 + i64::from(index));
        store.put_raw(
            crate::keys::due_key(engine.namespace(), &target_queue, target_due, &target_id)
                .expect("target due key is valid"),
            crate::keys::due_value(target_due).expect("target due value is valid"),
        );
    }
    store.put_raw(
        crate::keys::wake_key(engine.namespace(), &target_queue).expect("wake key is valid"),
        crate::keys::wake_value(Timestamp::from_millis(20)).expect("wake value is valid"),
    );

    let mut mutations = Vec::new();
    let wake_check = block_on(crate::transition::wake_mutation(
        &engine,
        &target_queue,
        None,
        None,
        &mut mutations,
    ))
    .expect("wake reconciliation succeeds");

    assert!(wake_check.is_none());
    assert!(
        mutations.is_empty(),
        "incomplete scan must not raise the watermark"
    );
    assert_eq!(
        store.range_reads(),
        1,
        "wake reconciliation reads one ordered page"
    );
}

#[test]
fn given_machine_sized_range_caps_when_reconciling_wake_then_the_page_is_library_bounded() {
    let store = RangeCountingStore::machine_sized();
    let engine = range_counting_system(store.clone());
    let target_queue = QueueName::try_new("default").expect("target queue is valid");

    block_on(crate::transition::wake_mutation(
        &engine,
        &target_queue,
        None,
        None,
        &mut Vec::new(),
    ))
    .expect("wake reconciliation succeeds");

    assert_eq!(store.range_reads(), 1);
    let requests = store.range_limits();
    assert_eq!(requests.len(), 1);
    let (items, bytes) = requests[0];
    assert!(
        items == crate::transition::MAX_INDEX_RANGE_ITEMS as u32,
        "machine-sized backend must be capped at the library item limit"
    );
    assert!(
        bytes == crate::transition::MAX_INDEX_RANGE_BYTES,
        "machine-sized backend must be capped at the library byte limit"
    );
}

#[derive(Clone)]
struct RangeCountingStore {
    inner: FakeStore,
    range_reads: Arc<AtomicUsize>,
    range_limits: Arc<Mutex<Vec<(u32, usize)>>>,
}

impl RangeCountingStore {
    fn new() -> Self {
        let capabilities = StoreCapabilities::try_from(StoreCapabilitiesInput {
            level: StoreLevel::Local,
            max_key_bytes: NonZeroUsize::new(4_096).expect("key limit is non-zero"),
            max_value_bytes: NonZeroUsize::new(1_048_576).expect("value limit is non-zero"),
            max_get_many_keys: NonZeroU32::new(1_024).expect("get-many limit is non-zero"),
            max_get_many_key_bytes: NonZeroUsize::new(2 * 1_048_576)
                .expect("get-many byte limit is non-zero"),
            max_transaction_bytes: NonZeroUsize::new(2 * 1_048_576)
                .expect("transaction limit is non-zero"),
            max_transaction_keys: NonZeroU32::new(128).expect("transaction keys are non-zero"),
            max_range_items: NonZeroU32::MIN,
            max_range_bytes: NonZeroUsize::new(4_096).expect("range limit is non-zero"),
            max_transaction_duration: Duration::from_secs(5),
        })
        .expect("paged capabilities are valid");
        Self::with_capabilities(capabilities)
    }

    fn machine_sized() -> Self {
        let capabilities = StoreCapabilities::try_from(StoreCapabilitiesInput {
            level: StoreLevel::Local,
            max_key_bytes: NonZeroUsize::new(4_096).expect("key limit is non-zero"),
            max_value_bytes: NonZeroUsize::new(1_048_576).expect("value limit is non-zero"),
            max_get_many_keys: NonZeroU32::new(1_024).expect("get-many limit is non-zero"),
            max_get_many_key_bytes: NonZeroUsize::new(2 * 1_048_576)
                .expect("get-many byte limit is non-zero"),
            max_transaction_bytes: NonZeroUsize::new(2 * 1_048_576)
                .expect("transaction limit is non-zero"),
            max_transaction_keys: NonZeroU32::new(128).expect("transaction keys are non-zero"),
            max_range_items: NonZeroU32::new(u32::MAX).expect("range items are non-zero"),
            max_range_bytes: NonZeroUsize::new(usize::MAX).expect("range bytes are non-zero"),
            max_transaction_duration: Duration::from_secs(5),
        })
        .expect("machine-sized capabilities are valid");
        Self::with_capabilities(capabilities)
    }

    fn with_capabilities(capabilities: StoreCapabilities) -> Self {
        Self {
            inner: FakeStore::with_capabilities(capabilities),
            range_reads: Arc::new(AtomicUsize::new(0)),
            range_limits: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn put_raw(&self, key: StoreKey, value: Bytes) {
        self.inner
            .put_raw(key, value)
            .expect("fixture entry is valid");
    }

    fn range_reads(&self) -> usize {
        self.range_reads.load(Ordering::SeqCst)
    }

    fn range_limits(&self) -> Vec<(u32, usize)> {
        self.range_limits
            .lock()
            .expect("range log is healthy")
            .clone()
    }
}

impl JobStore for RangeCountingStore {
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
        self.range_reads.fetch_add(1, Ordering::SeqCst);
        self.range_limits
            .lock()
            .expect("range log is healthy")
            .push((request.item_limit().get(), request.byte_limit().get()));
        self.inner.read_range(request).await
    }

    async fn commit(&self, transaction: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        self.inner.commit(transaction).await
    }
}

fn range_counting_system(store: RangeCountingStore) -> JobSystem<RangeCountingStore> {
    JobSystem::new(
        store,
        crate::JobCatalog::from_registry(
            crate::test_helper::registry(FairnessPolicy::low_volume()),
        ),
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        OwnerId::from([1; 16]),
        crate::test_helper::wake_scheduler(),
    )
}
