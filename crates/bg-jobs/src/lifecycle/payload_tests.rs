use std::{
    num::NonZeroU16,
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use sha2::{Digest, Sha256};

use crate::{
    ExecutionId, FairnessClass, FakeStore, FakeStoreError, JobId, JobKind, JobSystem, Namespace,
    OwnerId, PayloadManifest, Priority, QueueName,
    codec::{ValueCodec, ValueTag},
    error::JobSystemError,
    lifecycle::payload::{decode_payload, load_payload_and_cancellation},
    model::{JobPolicySnapshot, JobRecordV1, JobState, MAX_INLINE_PAYLOAD_BYTES},
    policy::{EffectMode, FairnessPolicy, RetryPolicy, RetryPreset},
    store::{
        CommitOutcome, JobStore, RangePage, RangeRequest, StoreCapabilities, StoreKey,
        StoreTransaction,
    },
    test_helper::block_on,
    time::Timestamp,
};

#[derive(Clone)]
struct RecordingStore {
    inner: FakeStore,
    many_calls: Arc<Mutex<Vec<Vec<StoreKey>>>>,
    next_many_values: Arc<Mutex<Option<Vec<Option<Bytes>>>>>,
}

impl RecordingStore {
    fn new(inner: FakeStore) -> Self {
        Self {
            inner,
            many_calls: Arc::new(Mutex::new(Vec::new())),
            next_many_values: Arc::new(Mutex::new(None)),
        }
    }

    fn set_next_many_values(&self, values: Vec<Option<Bytes>>) {
        *self
            .next_many_values
            .lock()
            .expect("bulk-read fixture lock is healthy") = Some(values);
    }

    fn many_calls(&self) -> Vec<Vec<StoreKey>> {
        self.many_calls
            .lock()
            .expect("bulk-read call lock is healthy")
            .clone()
    }
}

impl JobStore for RecordingStore {
    type Error = FakeStoreError;

    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, key: StoreKey) -> Result<Option<Bytes>, Self::Error> {
        self.inner.get(key).await
    }

    async fn get_many(&self, keys: &[StoreKey]) -> Result<Vec<Option<Bytes>>, Self::Error> {
        self.many_calls
            .lock()
            .expect("bulk-read call lock is healthy")
            .push(keys.to_vec());
        if let Some(values) = self
            .next_many_values
            .lock()
            .expect("bulk-read fixture lock is healthy")
            .take()
        {
            return Ok(values);
        }
        self.inner.get_many(keys).await
    }

    async fn read_range(&self, request: RangeRequest) -> Result<RangePage, Self::Error> {
        self.inner.read_range(request).await
    }

    async fn commit(&self, transaction: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        self.inner.commit(transaction).await
    }
}

fn test_system(store: RecordingStore) -> JobSystem<RecordingStore> {
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

fn record_for(total_length: u32, digest: [u8; 32], chunk_keys: Vec<StoreKey>) -> JobRecordV1 {
    JobRecordV1 {
        job_id: JobId::from([7; 16]),
        namespace: Namespace::try_new(b"jobs").expect("test namespace is valid"),
        queue: QueueName::try_new("default").expect("test queue is valid"),
        kind: JobKind::try_new("email").expect("test kind is valid"),
        schema_version: NonZeroU16::MIN,
        generation: 0,
        execution_id: ExecutionId::from([8; 16]),
        payload: PayloadManifest {
            total_length,
            digest,
            chunk_keys,
        },
        fairness: FairnessClass::low_volume(),
        ordering_key: None,
        priority: Priority::Default,
        created_at: Timestamp::ZERO,
        scheduled_at: Timestamp::ZERO,
        expires_at: None,
        policy: JobPolicySnapshot {
            effect_mode: EffectMode::Idempotent,
            cost_units: NonZeroU16::MIN,
            execution_timeout: Some(Duration::from_secs(1)),
            retry_policy: RetryPolicy::preset(RetryPreset::Interactive),
        },
        attempts: None,
        state: JobState::Scheduled,
        checkpoint: None,
        retention_deadline: Timestamp::from_millis(1),
        deduplication: None,
        revision: 1,
    }
}

const PAYLOAD_ALLOCATION_PROBE: &str = "BG_JOBS_PAYLOAD_ALLOCATION_PROBE";

fn run_allocation_probe_in_child(test_name: &str) -> bool {
    if std::env::var_os(PAYLOAD_ALLOCATION_PROBE).is_some() {
        return true;
    }

    let status = Command::new(std::env::current_exe().expect("test executable is available"))
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env(PAYLOAD_ALLOCATION_PROBE, "1")
        .status()
        .expect("allocation probe process starts");
    assert!(
        status.success(),
        "isolated allocation probe exited with {status:?}"
    );
    false
}

fn payload_fixture(bodies: &[&[u8]]) -> (JobRecordV1, Vec<(StoreKey, Bytes)>, StoreKey) {
    let job_id = JobId::from([7; 16]);
    let namespace = Namespace::try_new(b"jobs").expect("test namespace is valid");
    let chunk_keys = bodies
        .iter()
        .enumerate()
        .map(|(index, _)| {
            crate::keys::payload_key(&namespace, &job_id, index as u32)
                .expect("payload key is valid")
        })
        .collect::<Vec<_>>();
    let mut payload = Vec::new();
    let values = chunk_keys
        .iter()
        .zip(bodies)
        .map(|(key, body)| {
            payload.extend_from_slice(body);
            (
                key.clone(),
                ValueCodec::encode(ValueTag::PayloadChunk, body).expect("payload chunk encodes"),
            )
        })
        .collect();
    let digest = Sha256::digest(&payload).into();
    let record = record_for(payload.len() as u32, digest, chunk_keys);
    let cancellation_key =
        crate::keys::cancellation_key(&namespace, &job_id).expect("cancellation key is valid");
    (record, values, cancellation_key)
}

fn seed_payload(store: &FakeStore, values: &[(StoreKey, Bytes)]) {
    for (key, value) in values {
        store
            .put_raw(key.clone(), value.clone())
            .expect("payload fixture is within fake-store limits");
    }
}

#[test]
fn given_a_multi_chunk_payload_when_loading_then_one_ordered_bulk_read_includes_cancellation() {
    let (record, values, cancellation_key) = payload_fixture(&[b"ab", b"cdef"]);
    let inner = FakeStore::new();
    seed_payload(&inner, &values);
    let store = RecordingStore::new(inner);
    let system = test_system(store.clone());

    let (payload, cancellation) =
        block_on(load_payload_and_cancellation(&system, &record)).expect("payload load succeeds");

    assert_eq!(payload, Bytes::from_static(b"abcdef"));
    assert!(cancellation.is_none());
    let calls = store.many_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0],
        record
            .payload
            .chunk_keys
            .iter()
            .cloned()
            .chain(std::iter::once(cancellation_key))
            .collect::<Vec<_>>()
    );
}

#[test]
fn given_a_missing_cancellation_when_loading_then_missing_remains_none() {
    let (record, values, _) = payload_fixture(&[b"ab", b"cdef"]);
    let inner = FakeStore::new();
    seed_payload(&inner, &values);
    let store = RecordingStore::new(inner);
    let system = test_system(store);

    let (_, cancellation) =
        block_on(load_payload_and_cancellation(&system, &record)).expect("payload load succeeds");

    assert!(cancellation.is_none());
}

#[test]
fn given_missing_or_repeated_bulk_results_when_loading_then_payload_is_corrupt() {
    let (record, values, _) = payload_fixture(&[b"ab", b"cdef"]);
    let encoded = values
        .iter()
        .map(|(_, value)| value.clone())
        .collect::<Vec<_>>();
    for result in [
        vec![None, Some(encoded[1].clone()), None],
        vec![Some(encoded[0].clone()), Some(encoded[0].clone()), None],
        vec![Some(encoded[0].clone()), Some(encoded[1].clone())],
        vec![
            Some(encoded[0].clone()),
            Some(encoded[1].clone()),
            None,
            None,
        ],
    ] {
        let inner = FakeStore::new();
        seed_payload(&inner, &values);
        let store = RecordingStore::new(inner);
        store.set_next_many_values(result);
        let system = test_system(store);

        let error = block_on(load_payload_and_cancellation(&system, &record))
            .expect_err("invalid bulk result must fail closed");
        assert!(matches!(error, JobSystemError::PayloadCorrupt));
    }
}

#[test]
fn given_an_oversized_manifest_when_decoding_then_no_payload_buffer_is_allocated() {
    if !run_allocation_probe_in_child(
        "given_an_oversized_manifest_when_decoding_then_no_payload_buffer_is_allocated",
    ) {
        return;
    }

    let record = record_for(
        (MAX_INLINE_PAYLOAD_BYTES + 1) as u32,
        [0; 32],
        vec![StoreKey::try_from(&b"chunk"[..]).expect("chunk key is valid")],
    );
    let encoded =
        ValueCodec::encode(ValueTag::PayloadChunk, b"valid").expect("payload chunk encodes");

    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "given_an_oversized_manifest_when_decoding_then_no_payload_buffer_is_allocated",
        file!(),
        line!(),
        Some("payload-bound"),
    );
    let error = decode_payload::<FakeStoreError, _>(&record, [Some(encoded)])
        .expect_err("oversized manifest must fail closed");
    let allocations = guard.finish();

    assert!(matches!(error, JobSystemError::PayloadCorrupt));
    assert_eq!(allocations.allocation_count, 0);
    assert_eq!(allocations.allocated_bytes, 0);
}

#[test]
fn given_individually_valid_chunks_that_exceed_the_manifest_when_decoding_then_no_growth_occurs() {
    if !run_allocation_probe_in_child(
        "given_individually_valid_chunks_that_exceed_the_manifest_when_decoding_then_no_growth_occurs",
    ) {
        return;
    }

    let record = record_for(
        4,
        [0; 32],
        vec![
            StoreKey::try_from(&b"chunk-0"[..]).expect("chunk key is valid"),
            StoreKey::try_from(&b"chunk-1"[..]).expect("chunk key is valid"),
        ],
    );
    let encoded = [
        Some(ValueCodec::encode(ValueTag::PayloadChunk, b"abc").expect("chunk encodes")),
        Some(ValueCodec::encode(ValueTag::PayloadChunk, b"de").expect("chunk encodes")),
    ];

    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "given_individually_valid_chunks_that_exceed_the_manifest_when_decoding_then_no_growth_occurs",
        file!(),
        line!(),
        Some("payload-bound"),
    );
    let error = decode_payload::<FakeStoreError, _>(&record, encoded)
        .expect_err("aggregate payload must fail before extending beyond manifest");
    let allocations = guard.finish();

    assert!(matches!(error, JobSystemError::PayloadCorrupt));
    assert!(allocations.allocated_bytes <= 4);
}

#[test]
fn given_a_payload_at_the_global_limit_when_decoding_then_boundary_bytes_are_accepted() {
    let first = vec![b'a'; MAX_INLINE_PAYLOAD_BYTES / 2];
    let second = vec![b'b'; MAX_INLINE_PAYLOAD_BYTES - first.len()];
    let mut payload = first.clone();
    payload.extend_from_slice(&second);
    let keys = vec![
        StoreKey::try_from(&b"chunk-0"[..]).expect("chunk key is valid"),
        StoreKey::try_from(&b"chunk-1"[..]).expect("chunk key is valid"),
    ];
    let record = record_for(
        MAX_INLINE_PAYLOAD_BYTES as u32,
        Sha256::digest(&payload).into(),
        keys,
    );
    let encoded = [
        Some(
            ValueCodec::encode(ValueTag::PayloadChunk, &first)
                .expect("first boundary chunk encodes"),
        ),
        Some(
            ValueCodec::encode(ValueTag::PayloadChunk, &second)
                .expect("second boundary chunk encodes"),
        ),
    ];

    let decoded = decode_payload::<FakeStoreError, _>(&record, encoded)
        .expect("payload at the global boundary remains valid");

    assert_eq!(decoded.len(), MAX_INLINE_PAYLOAD_BYTES);
    assert_eq!(decoded, Bytes::from(payload));
}
