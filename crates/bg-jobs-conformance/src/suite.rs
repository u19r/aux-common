use std::{
    fmt,
    num::{NonZeroU32, NonZeroUsize},
    sync::atomic::{AtomicU64, Ordering},
};

use bg_jobs::store::{
    Check, CommitOperationId, CommitOutcome, JobStore, Mutation, RangeDirection, RangePage,
    RangeRequest, RangeRequestInput, StoreContractError, StoreKey, StoreTransaction,
    StoreTransactionInput, TransactionLimits,
};
use bytes::Bytes;

use crate::{CountingStore, OperationCounts, constants::DEFAULT_KEY_PREFIX};
static NEXT_RUN_ID: AtomicU64 = AtomicU64::new(1);

/// Namespaced keys and bounds used by a conformance run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConformanceConfig {
    key_prefix: Vec<u8>,
    range_items: NonZeroU32,
    range_bytes: NonZeroUsize,
}

impl Default for ConformanceConfig {
    fn default() -> Self {
        Self::isolated()
    }
}

impl ConformanceConfig {
    /// Creates a run configuration with a process-unique key namespace.
    ///
    /// A default configuration must not delete another run's fixtures when
    /// multiple proofs share one backend. Consumers running proofs across
    /// processes should use [`Self::try_new`] with an externally unique
    /// prefix instead.
    pub fn isolated() -> Self {
        let run_id = NEXT_RUN_ID.fetch_add(1, Ordering::Relaxed);
        let mut key_prefix = DEFAULT_KEY_PREFIX.to_vec();
        key_prefix.extend_from_slice(run_id.to_string().as_bytes());
        key_prefix.push(b'/');
        Self {
            key_prefix,
            range_items: NonZeroU32::new(2).unwrap_or(NonZeroU32::MIN),
            range_bytes: NonZeroUsize::new(1_024).unwrap_or(NonZeroUsize::MIN),
        }
    }

    /// Creates a configuration with a caller-owned, non-empty key namespace.
    ///
    /// The caller is responsible for making this prefix unique when multiple
    /// processes share a backend.
    pub fn try_new(
        key_prefix: impl AsRef<[u8]>,
        range_items: NonZeroU32,
        range_bytes: NonZeroUsize,
    ) -> Result<Self, ConformanceConfigError> {
        let key_prefix = key_prefix.as_ref().to_vec();
        if key_prefix.is_empty() {
            return Err(ConformanceConfigError::EmptyPrefix);
        }
        Ok(Self {
            key_prefix,
            range_items,
            range_bytes,
        })
    }

    pub(crate) fn key(&self, suffix: &[u8]) -> Result<StoreKey, &'static str> {
        let mut bytes = self.key_prefix.clone();
        bytes.extend_from_slice(suffix);
        StoreKey::try_from(bytes).map_err(|_| "conformance key")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConformanceConfigError {
    EmptyPrefix,
}

impl fmt::Display for ConformanceConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("conformance key prefix is empty")
    }
}

impl std::error::Error for ConformanceConfigError {}

/// Aggregate evidence from one basic contract run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConformanceReport {
    pub assertions: u32,
    pub reads: u32,
    pub get_many: u32,
    pub ranges: u32,
    pub commits: u32,
    pub conflicts: u32,
    pub unknowns: u32,
}

impl ConformanceReport {
    fn assertion<E>(
        mut self,
        condition: bool,
        message: &'static str,
    ) -> Result<Self, ConformanceError<E>> {
        self.assertions += 1;
        if condition {
            Ok(self)
        } else {
            Err(ConformanceError::Invalid(message))
        }
    }
}

/// Store-operation and byte evidence from a fixed debug workload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationProfile {
    pub report: ConformanceReport,
    pub counts: OperationCounts,
}

/// Errors returned by a reusable conformance run.
#[derive(Debug)]
pub enum ConformanceError<E> {
    Store(E),
    Contract(StoreContractError),
    Invalid(&'static str),
}

impl<E: fmt::Display> fmt::Display for ConformanceError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::Contract(error) => error.fmt(formatter),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl<E: fmt::Debug + fmt::Display + 'static> std::error::Error for ConformanceError<E> {}

impl<E> From<StoreContractError> for ConformanceError<E> {
    fn from(error: StoreContractError) -> Self {
        Self::Contract(error)
    }
}

/// Proves absent reads, ordered bulk reads, bounded pages, checked atomic
/// commits, conflicts, and deletes for a caller-supplied store.
///
/// The caller supplies the backend so the same proof can exercise a
/// production adapter. The fake/reference stores in aux-common remain test
/// infrastructure and are not production persistence.
pub async fn run_basic<S: JobStore>(
    store: &S,
    config: &ConformanceConfig,
) -> Result<ConformanceReport, ConformanceError<S::Error>> {
    let keys = [
        config.key(b"basic/a").map_err(ConformanceError::Invalid)?,
        config.key(b"basic/b").map_err(ConformanceError::Invalid)?,
        config.key(b"basic/c").map_err(ConformanceError::Invalid)?,
        config.key(b"basic/").map_err(ConformanceError::Invalid)?,
        config.key(b"basic").map_err(ConformanceError::Invalid)?,
        config
            .key(b"basic/\xff")
            .map_err(ConformanceError::Invalid)?,
        config
            .key(b"basic/\xff\0")
            .map_err(ConformanceError::Invalid)?,
        config
            .key(b"atomic/new")
            .map_err(ConformanceError::Invalid)?,
        config
            .key(b"replay/value")
            .map_err(ConformanceError::Invalid)?,
        config
            .key(b"replay/conflict")
            .map_err(ConformanceError::Invalid)?,
    ];
    cleanup(store, &keys).await?;
    let report = basic_insert(store, &keys[0], &keys[1]).await?;
    let report = basic_get_many(store, &keys[..3], report).await?;
    let report = basic_range(store, config, &keys, report).await?;
    let report = basic_atomic_conflict(store, &keys, report).await?;
    let report = basic_conflict(store, &keys[0], report).await?;
    let report = basic_exact_commit_reuse(store, &keys[8], &keys[9], report).await?;
    cleanup(store, &keys).await?;
    Ok(report)
}

async fn basic_insert<S: JobStore>(
    store: &S,
    present_a: &StoreKey,
    present_b: &StoreKey,
) -> Result<ConformanceReport, ConformanceError<S::Error>> {
    let mut report = ConformanceReport::default();
    let missing = store
        .get(present_a.clone())
        .await
        .map_err(ConformanceError::Store)?
        .is_none();
    report = report.assertion(missing, "missing read was present")?;
    report.reads += 1;
    let put = transaction(
        store,
        vec![Check::Absent(present_a.clone())],
        vec![
            Mutation::Put(present_a.clone(), Bytes::from_static(b"a")),
            Mutation::Put(present_b.clone(), Bytes::from_static(b"b")),
        ],
    )?;
    let committed = store.commit(&put).await.map_err(ConformanceError::Store)?;
    report.commits += 1;
    report = report.assertion(
        committed == CommitOutcome::Committed,
        "initial put did not commit",
    )?;
    let value = store
        .get(present_a.clone())
        .await
        .map_err(ConformanceError::Store)?;
    report.reads += 1;
    report.assertion(
        value.as_deref() == Some(&b"a"[..]),
        "committed value was not readable",
    )
}

async fn basic_get_many<S: JobStore>(
    store: &S,
    keys: &[StoreKey],
    mut report: ConformanceReport,
) -> Result<ConformanceReport, ConformanceError<S::Error>> {
    let empty = store.get_many(&[]).await.map_err(ConformanceError::Store)?;
    report.get_many += 1;
    report = report.assertion(empty.is_empty(), "empty get_many was not empty")?;
    let values = store
        .get_many(&[
            keys[0].clone(),
            keys[2].clone(),
            keys[0].clone(),
            keys[1].clone(),
        ])
        .await
        .map_err(ConformanceError::Store)?;
    report.get_many += 1;
    report = report.assertion(values.len() == 4, "get_many cardinality changed")?;
    report.assertion(
        values
            == vec![
                Some(Bytes::from_static(b"a")),
                None,
                Some(Bytes::from_static(b"a")),
                Some(Bytes::from_static(b"b")),
            ],
        "get_many order, duplicate, or missing-value semantics changed",
    )
}

async fn basic_range<S: JobStore>(
    store: &S,
    config: &ConformanceConfig,
    keys: &[StoreKey],
    report: ConformanceReport,
) -> Result<ConformanceReport, ConformanceError<S::Error>> {
    let report = seed_range(store, keys, report).await?;
    check_range(store, config, keys, report).await
}

async fn seed_range<S: JobStore>(
    store: &S,
    keys: &[StoreKey],
    mut report: ConformanceReport,
) -> Result<ConformanceReport, ConformanceError<S::Error>> {
    let seed = transaction(
        store,
        vec![],
        vec![
            Mutation::Put(keys[2].clone(), Bytes::from_static(b"c")),
            Mutation::Put(keys[3].clone(), Bytes::from_static(b"start")),
            Mutation::Put(keys[4].clone(), Bytes::from_static(b"before")),
            Mutation::Put(keys[5].clone(), Bytes::from_static(b"end")),
            Mutation::Put(keys[6].clone(), Bytes::from_static(b"after")),
        ],
    )?;
    let committed = store.commit(&seed).await.map_err(ConformanceError::Store)?;
    report.commits += 1;
    report.assertion(
        committed == CommitOutcome::Committed,
        "range seed did not commit",
    )
}

async fn check_range<S: JobStore>(
    store: &S,
    config: &ConformanceConfig,
    keys: &[StoreKey],
    report: ConformanceReport,
) -> Result<ConformanceReport, ConformanceError<S::Error>> {
    let forward = vec![
        keys[3].clone(),
        keys[0].clone(),
        keys[1].clone(),
        keys[2].clone(),
    ];
    let reverse = forward.iter().cloned().rev().collect::<Vec<_>>();
    let report = check_direction(
        store,
        RangeProof {
            config,
            expected: &forward,
            direction: RangeDirection::Forward,
        },
        report,
    )
    .await?;
    check_direction(
        store,
        RangeProof {
            config,
            expected: &reverse,
            direction: RangeDirection::Reverse,
        },
        report,
    )
    .await
}

struct RangeProof<'a> {
    config: &'a ConformanceConfig,
    expected: &'a [StoreKey],
    direction: RangeDirection,
}

async fn check_direction<S: JobStore>(
    store: &S,
    proof: RangeProof<'_>,
    mut report: ConformanceReport,
) -> Result<ConformanceReport, ConformanceError<S::Error>> {
    let mut input = request_input(proof.config, b"basic/", proof.direction)
        .map_err(ConformanceError::Invalid)?;
    let mut seen = Vec::new();
    let mut finished = false;
    for _ in 0..=proof.expected.len() {
        let request = RangeRequest::try_from(input.clone())
            .map_err(|_| ConformanceError::Invalid("range request"))?;
        let page = store
            .read_range(request)
            .await
            .map_err(ConformanceError::Store)?;
        report.ranges += 1;
        validate_page(&page, proof.direction, proof.config, &mut seen)
            .map_err(ConformanceError::Invalid)?;
        let Some(cursor) = page.continuation else {
            finished = true;
            break;
        };
        let last = page.entries.last().ok_or(ConformanceError::Invalid(
            "empty range page had continuation",
        ))?;
        if cursor != last.key {
            return Err(ConformanceError::Invalid(
                "range continuation did not identify the last entry",
            ));
        }
        input.continuation = Some(cursor);
    }
    report = report.assertion(finished, "range continuation exceeded proof bound")?;
    report.assertion(
        seen == proof.expected,
        "range order, bounds, or continuation changed",
    )
}

fn validate_page(
    page: &RangePage,
    direction: RangeDirection,
    config: &ConformanceConfig,
    seen: &mut Vec<StoreKey>,
) -> Result<(), &'static str> {
    if page.entries.is_empty() || page.entries.len() > config.range_items.get() as usize {
        return Err("range page item bound changed");
    }
    if page.total_bytes() > config.range_bytes.get() {
        return Err("range page byte bound changed");
    }
    let ordered = page.entries.windows(2).all(|entries| match direction {
        RangeDirection::Forward => entries[0].key < entries[1].key,
        RangeDirection::Reverse => entries[0].key > entries[1].key,
    });
    if !ordered {
        return Err("range page order changed");
    }
    seen.extend(page.entries.iter().map(|entry| entry.key.clone()));
    Ok(())
}

async fn basic_atomic_conflict<S: JobStore>(
    store: &S,
    keys: &[StoreKey],
    mut report: ConformanceReport,
) -> Result<ConformanceReport, ConformanceError<S::Error>> {
    let transaction = transaction(
        store,
        vec![
            Check::Value(keys[0].clone(), Bytes::from_static(b"a")),
            Check::Value(keys[1].clone(), Bytes::from_static(b"stale")),
        ],
        vec![
            Mutation::Put(keys[0].clone(), Bytes::from_static(b"wrong")),
            Mutation::Put(keys[7].clone(), Bytes::from_static(b"partial")),
        ],
    )?;
    let result = store
        .commit(&transaction)
        .await
        .map_err(ConformanceError::Store)?;
    report.commits += 1;
    report.conflicts += 1;
    report = report.assertion(
        result == CommitOutcome::Conflict,
        "multi-key checked conflict was accepted",
    )?;
    let values = store
        .get_many(&[keys[0].clone(), keys[7].clone()])
        .await
        .map_err(ConformanceError::Store)?;
    report.get_many += 1;
    report.assertion(
        values == vec![Some(Bytes::from_static(b"a")), None],
        "multi-key conflict partially mutated state",
    )
}

async fn basic_conflict<S: JobStore>(
    store: &S,
    key: &StoreKey,
    mut report: ConformanceReport,
) -> Result<ConformanceReport, ConformanceError<S::Error>> {
    let conflict = transaction(
        store,
        vec![Check::Value(key.clone(), Bytes::from_static(b"stale"))],
        vec![Mutation::Put(key.clone(), Bytes::from_static(b"wrong"))],
    )?;
    let result = store
        .commit(&conflict)
        .await
        .map_err(ConformanceError::Store)?;
    report.commits += 1;
    report.conflicts += 1;
    report = report.assertion(
        result == CommitOutcome::Conflict,
        "stale checked commit was accepted",
    )?;
    let value = store
        .get(key.clone())
        .await
        .map_err(ConformanceError::Store)?;
    report.reads += 1;
    report.assertion(
        value.as_deref() == Some(&b"a"[..]),
        "conflict mutated the value",
    )
}

async fn basic_exact_commit_reuse<S: JobStore>(
    store: &S,
    replay_key: &StoreKey,
    conflict_key: &StoreKey,
    mut report: ConformanceReport,
) -> Result<ConformanceReport, ConformanceError<S::Error>> {
    let operation_id = commit_operation_id().map_err(ConformanceError::Invalid)?;
    let committed = transaction_with_operation_id(
        store,
        operation_id,
        vec![Check::Absent(replay_key.clone())],
        vec![Mutation::Put(
            replay_key.clone(),
            Bytes::from_static(b"committed"),
        )],
    )?;
    for _ in 0..2 {
        let outcome = store
            .commit(&committed)
            .await
            .map_err(ConformanceError::Store)?;
        report.commits += 1;
        report = report.assertion(
            outcome == CommitOutcome::Committed,
            "committed operation replay changed outcome",
        )?;
    }
    let mismatched = transaction_with_operation_id(
        store,
        operation_id,
        vec![],
        vec![Mutation::Put(
            conflict_key.clone(),
            Bytes::from_static(b"mismatch"),
        )],
    )?;
    report = report.assertion(
        store.commit(&mismatched).await.is_err(),
        "commit operation ID accepted different transaction content",
    )?;

    let conflict = transaction(
        store,
        vec![Check::Absent(replay_key.clone())],
        vec![Mutation::Put(
            conflict_key.clone(),
            Bytes::from_static(b"wrong"),
        )],
    )?;
    let first_conflict = store
        .commit(&conflict)
        .await
        .map_err(ConformanceError::Store)?;
    report.commits += 1;
    report.conflicts += 1;
    report = report.assertion(
        first_conflict == CommitOutcome::Conflict,
        "initial exact-reuse conflict changed outcome",
    )?;
    let delete = transaction(
        store,
        vec![Check::Value(
            replay_key.clone(),
            Bytes::from_static(b"committed"),
        )],
        vec![Mutation::Delete(replay_key.clone())],
    )?;
    let deleted = store
        .commit(&delete)
        .await
        .map_err(ConformanceError::Store)?;
    report.commits += 1;
    report = report.assertion(
        deleted == CommitOutcome::Committed,
        "exact-reuse fixture deletion did not commit",
    )?;
    let replayed_conflict = store
        .commit(&conflict)
        .await
        .map_err(ConformanceError::Store)?;
    report.commits += 1;
    report.conflicts += 1;
    report = report.assertion(
        replayed_conflict == CommitOutcome::Conflict,
        "conflict operation replay changed outcome",
    )?;
    let values = store
        .get_many(&[replay_key.clone(), conflict_key.clone()])
        .await
        .map_err(ConformanceError::Store)?;
    report.get_many += 1;
    report.assertion(
        values == vec![None, None],
        "commit operation replay applied a mutation more than once",
    )
}

/// Runs the basic contract against an operation-counting wrapper and returns
/// exact debug-build store amplification evidence.
pub async fn run_operation_profile<S: JobStore>(
    store: &CountingStore<S>,
    config: &ConformanceConfig,
) -> Result<OperationProfile, ConformanceError<S::Error>> {
    store.reset();
    let report = run_basic(store, config).await?;
    let counts = store.snapshot();
    Ok(OperationProfile { report, counts })
}

pub(crate) async fn cleanup<S: JobStore>(
    store: &S,
    keys: &[StoreKey],
) -> Result<(), ConformanceError<S::Error>> {
    let transaction = transaction(
        store,
        vec![],
        keys.iter().cloned().map(Mutation::Delete).collect(),
    )?;
    let outcome = store
        .commit(&transaction)
        .await
        .map_err(ConformanceError::Store)?;
    if outcome == CommitOutcome::Conflict {
        return Err(ConformanceError::Invalid("cleanup delete conflicted"));
    }
    let values = store
        .get_many(keys)
        .await
        .map_err(ConformanceError::Store)?;
    if values.len() != keys.len() || values.iter().any(|value| value.is_some()) {
        return Err(ConformanceError::Invalid(
            "cleanup delete was not readable as absent",
        ));
    }
    Ok(())
}

pub(crate) fn put_transaction<S: JobStore>(
    store: &S,
    key: &StoreKey,
    value: &[u8],
) -> Result<StoreTransaction, ConformanceError<S::Error>> {
    transaction(
        store,
        vec![],
        vec![Mutation::Put(key.clone(), Bytes::copy_from_slice(value))],
    )
}

pub(crate) fn transaction<S: JobStore>(
    store: &S,
    checks: Vec<Check>,
    mutations: Vec<Mutation>,
) -> Result<StoreTransaction, ConformanceError<S::Error>> {
    transaction_with_operation_id(
        store,
        commit_operation_id().map_err(ConformanceError::Invalid)?,
        checks,
        mutations,
    )
}

fn transaction_with_operation_id<S: JobStore>(
    store: &S,
    operation_id: CommitOperationId,
    checks: Vec<Check>,
    mutations: Vec<Mutation>,
) -> Result<StoreTransaction, ConformanceError<S::Error>> {
    let capabilities = store.capabilities();
    StoreTransaction::try_from(StoreTransactionInput {
        operation_id,
        checks,
        mutations,
        limits: TransactionLimits {
            max_checks: capabilities.max_transaction_keys(),
            max_mutations: capabilities.max_transaction_keys(),
            max_bytes: capabilities.max_transaction_bytes(),
        },
    })
    .map_err(ConformanceError::Contract)
}

fn commit_operation_id() -> Result<CommitOperationId, &'static str> {
    CommitOperationId::generate().map_err(|_| "commit operation entropy")
}

fn request_input(
    config: &ConformanceConfig,
    prefix: &[u8],
    direction: RangeDirection,
) -> Result<RangeRequestInput, &'static str> {
    let start = config.key(prefix)?.into_bytes();
    let mut end = start.clone();
    end.push(0xff);
    Ok(RangeRequestInput {
        start: Some(StoreKey::try_from(start).map_err(|_| "range start")?),
        end: Some(StoreKey::try_from(end).map_err(|_| "range end")?),
        direction,
        item_limit: config.range_items,
        byte_limit: config.range_bytes,
        continuation: None,
    })
}
