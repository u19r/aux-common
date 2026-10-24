# Buffered writes

`BufferedWrites<T>` retains write items and delivers stable batches through a caller-owned sink.
The default flush rule is **200 ms oldest age OR 25 items**. The default item capacity is 25.
The engine checks age after responses. It does not start a timer during construction.

This example uses an in-memory transaction to show the receipt contract. It proves no process-crash durability.
A production atomic sink must commit its receipt and all destination effects in the same transaction.

```rust
use std::{collections::BTreeMap, sync::{Arc, Mutex}, time::Duration};
use buffered_writes::{AtomicSink, AtomicWriteStatus, BatchId, BufferedWrites,
    SinkError, SinkLimits, WriteAttempt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(Mutex::new((BTreeMap::<BatchId, [u8; 32]>::new(), 0_u64)));
    let destination = store.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u64>| {
        let destination = destination.clone();
        async move {
            let mut store = destination.lock().map_err(|_| SinkError::retryable("store unavailable"))?;
            if let Some(digest) = store.0.get(&attempt.batch_id()) {
                return if digest == attempt.digest() {
                    Ok(AtomicWriteStatus::AlreadyApplied)
                } else {
                    Err(SinkError::identity_conflict())
                };
            }
            store.1 += attempt.items().iter().sum::<u64>();
            store.0.insert(attempt.batch_id(), *attempt.digest());
            Ok(AtomicWriteStatus::Applied)
        }
    })?;
    let writer = BufferedWrites::builder("example/totals/v1", sink).build()?;
    assert!(writer.add_write_item(7).await?.is_buffered());
    writer.add_write_item_with(|| Ok(3)).await?;
    // Call after_response only after the host has completed the response body.
    writer.after_response().await;
    writer.flush_writes().await;
    assert_eq!(store.lock().map_err(|_| "store unavailable")?.1, 10);
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
    Ok(())
}
```

`Buffered` confirms admission under the selected retention contract. It does not mean the destination committed the write.
A full buffer rejects new items by default. Leased work still consumes capacity until settlement.
The item capacity also bounds concurrent submission calls, including callers waiting for capacity.
Excess calls return `Full` without joining an internal wait queue.
`WaitUntilDeadline` requests capacity from the driver and waits for retention space; it never calls
or awaits the sink directly. This request may force eligibility at the next permitted lifecycle
window, even under a false custom predicate. Without such a window it expires without invoking
the factory or sink. Only synchronous delivery mode directly awaits destination settlement.
Factories and encoding share one local admission turn. Waiting for that turn is deadline-bound and
counts against the submission limit. A factory runs only after staging capacity is available and runs
at most once, including a capacity wait that re-encodes its owned item. Provider-full retries keep
the already encoded record. The factory's private allocations remain the caller's responsibility.
Items do not need to implement `Clone`. Cloning writer, sink, attempt, or pending-item handles shares their existing state.

The JSON codec stops at the selected canonical input byte limit. That limit also accounts for
available staging space after modeled record and receipt overhead. Temporary byte pressure returns
`Full`, or waits under the configured policy; an item that cannot fit an empty buffer is oversized. Direct grouping uses destination
limits for early input rejection. Custom preparation uses retention capacity for canonical input and
checks native output limits independently. Packed and multiple-command helpers enforce output
limits during encoding; output operation count is independent of retained input count. They also
bound command metadata, identity arrays, and completion-tracking space through one operation builder.
Admission reserves the record, its receipt, and its sealing/quarantine budget before accepting it.
Custom preparation reserves native output bytes and worst-case operation metadata, limited by the
configured byte capacity. This can reduce the number of accepted items below the item limit.
Advanced preparation can inspect `BatchItems::max_prepared_bytes`: it is the reserved allowance left
after canonical replay records and sealed-entry headers. Oversized singleton output is quarantined
within its reservation; sealing also checks the provider capacity atomically.
A custom `RecordCodec` must honor the byte budget passed to `encode` and stop output when exhausted. It can delegate to `SerdeJsonCodec::encode` for bounded JSON output; the engine also rejects oversized returned bytes.
Admission also checks custom codec output before retaining it. Oversize errors report a lower bound when encoding stops early.
Caller factories, custom serializers, decoders, and sink implementations own their additional allocations and execution time.
These payload limits do not impose a hard limit on total process memory.

Use the same policy interface for defaults, threshold overrides, and predicates:

```rust
use buffered_writes::{BufferCapacity, BufferStats, FlushPolicy, FlushThresholds};
use std::time::Duration;

let thresholds = FlushThresholds::default()
    .max_age(Duration::from_millis(500))
    .max_items(100)
    .max_bytes(32 * 1024);
let capacity = BufferCapacity::default().max_items(500);
let predicate = move |stats: &BufferStats| thresholds.should_flush(stats);
// Pass these to .flush_policy(predicate) and .buffer_capacity(capacity).
# let _ = (predicate, capacity);
```

A predicate replaces the default rule. It cannot bypass capacity or destination limits.
Use `prepare_with(version, closure)` to persist a packed value or several prepared operations per batch.
Use `PartialSink` for independently idempotent operations with partial responses.
The engine seals preparation once and retries the same identities and payloads.

For one packed command, the closure can combine all admitted items. This sink fixture checks the command without destination effects.
Use a transaction-backed sink for production writes.

```rust
use buffered_writes::{AtomicSink, BufferedWrites, PreparedWrites, SinkError, SinkLimits, WriteAttempt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sink = AtomicSink::try_new(SinkLimits::try_new(1, 64)?, |attempt: WriteAttempt<u32>| async move {
        assert_eq!(attempt.pending_operations().len(), 1);
        assert_eq!(attempt.decode_packed::<u32>().map_err(|_| SinkError::permanent("invalid sum"))?, 10);
        Ok::<(), SinkError>(())
    })?;
    let writer = BufferedWrites::builder("example/packed/v1", sink)
        .prepare_with("sum/v1", |batch| {
            PreparedWrites::packed(&batch, &batch.items().iter().sum::<u32>())
        }).build()?;
    writer.add_write_item(3).await?;
    writer.add_write_item(7).await?;
    assert_eq!(writer.flush_writes().await.items_settled, 2);
    Ok(())
}
```

For several commands, return an iterator of serializable values. The engine assigns stable operation IDs before delivery.
The sink can submit them in one atomic transaction or report partial progress through `PartialSink`.
This fixture checks four commands from two admitted items; it performs no destination writes.

```rust
use buffered_writes::{AtomicSink, BufferCapacity, BufferedWrites, PreparedWrites, SinkError, SinkLimits, WriteAttempt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sink = AtomicSink::try_new(SinkLimits::default(), |attempt: WriteAttempt<u32>| async move {
        let commands = attempt.pending_operations().iter()
            .map(|operation| serde_json::from_slice::<u32>(&operation.payload))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SinkError::permanent("invalid commands"))?;
        assert_eq!(commands, [3, 30, 7, 70]);
        Ok::<(), SinkError>(())
    })?;
    let writer = BufferedWrites::builder("example/commands/v1", sink)
        .buffer_capacity(BufferCapacity::default().max_items(2))
        .prepare_with("two-effects/v1", |batch| {
            PreparedWrites::operations(&batch, batch.items().iter().flat_map(|item| [*item, item * 10]))
        }).build()?;
    writer.add_write_item_with(|| Ok(3)).await?;
    writer.add_write_item_with(|| Ok(7)).await?;
    assert_eq!(writer.flush_writes().await.items_settled, 2);
    Ok(())
}
```

Sealed envelopes expose read-only accessors. Construction and deserialization reject invalid membership, versions, UUIDs, and digests.
The digest format is `aux-buffered-writes/batch/v2`; the disk journal version is 8.
Earlier experimental envelopes and journals are rejected. No compatibility reader is maintained for these pre-production formats.

Memory is the default retention provider. Disk and Valkey require their Cargo features and explicit resource configuration.
Memory can lose accepted writes on process termination. Local disk can lose writes when its host or ephemeral volume disappears.
Valkey durability depends on persistence, replication, eviction, and failover configuration.
`shutdown(deadline)` attempts a bounded drain; inspect its report before treating shutdown as clean.
`state_unknown` means the drain could not establish all remaining ownership.
Shutdown closes admission and waits for calls already constructing or appending items.
A cancelled or timed-out append remains unknown until a retained admission receipt confirms its outcome.
Unknown appends retain both item and byte credits; retry the original operation identity and bytes
to reconcile them. A typed `AdmissionReceipt` binds operation ID, scope, codec version, and encoded
content. An ID/status lookup with a different fingerprint cannot clear unknown ownership. The same
fingerprint is required before synchronous acknowledgement. Advanced buffer providers compute it
with `AdmittedRecord::admission_fingerprint()` and retain it with their receipt.
Remote state and metadata use format v5; prior formats are rejected without rewriting them.
`unresolved_admissions` lists dispatched identities whose outcomes remain unresolved.
These local admission records are volatile; durable provider recovery owns accepted work after a process loss.
A `FlushReport` can contain `buffer_error` independently of a sink error.

For replay, use the producer's namespace, codec, strategy version, and destination receipt contract:

```rust
use buffered_writes::{AtomicSink, ConfigurationError, ReplayQueue, ReplayWorker};

fn configure_replay(
    queue: impl ReplayQueue,
    sink: AtomicSink<u64>,
) -> Result<ReplayWorker<u64>, ConfigurationError> {
    ReplayWorker::builder("example/totals/v1", queue, sink).build()
}
```

Replay renews visibility before a bounded attempt. It acknowledges only complete delivery.
Unknown outcomes and incomplete partial responses retain the original envelope for retry.
The queue adapter must preserve the versioned JSON quarantine record before removing the source
message. Format v1 contains `version`, `reason`, `envelope_base64` (the exact original bytes), and
`completed_operation_ids`. Permanent partial replay preserves known progress without rewriting the
sealed batch or claiming rollback. `ReplayReport::partial_operations_completed` and `PartialProgress`
expose that progress. Quarantine bodies are larger than source envelopes because of base64 and
metadata; configure destination quotas accordingly. A failed quarantine publication retains the source;
replaying it still requires the sink's declared idempotency guarantees.
Repeated delivery is safe only when the sink implements its declared atomic or independently idempotent receipt contract.

Retention mutations require both the matching fence and an active, unexpired lease. Expiry alone
ends authority even when another worker has not claimed the batch. Partial progress checkpoints
completed operations while retaining that lease; the engine retries under it or explicitly releases
it once at the end of the turn. A released lease cannot renew or settle work. The shared provider
fixture in `tests/support/lease_contract.rs` runs against memory, disk, and the native remote provider.
Recovered batch entries must match their map identity, and completion IDs must belong to the
immutable batch. Disk recovery quarantines invalid checkpoint frames and blocks further mutation;
remote operations reject invalid state without rewriting it.

Each retention provider owns one immutable validated namespace. `build()` rejects a custom provider
whose namespace differs from the writer. Default memory/disk construction uses the writer namespace
automatically; advanced `MemoryBuffer::new(namespace)` and `DiskBuffer::open(namespace, path)`
make ownership explicit. Namespace-free memory defaults are removed. Disk snapshots and remote
state/metadata persist this ownership; another namespace cannot reinterpret retained open records
or reuse completed receipts. The remote provider reads and validates both keys as a pair.
Its atomic replacement compares presence and exact previous bytes for each key; inspection rejects
an incomplete pair without fetching retained payloads. Fixed provider configuration and transport allocations remain outside
per-write capacity charges.

All runtime work is explicit. Call `start(lifecycle)` when periodic ticks or a lifecycle driver are required.
The host owns response completion, termination signals, and shutdown deadlines.
Buffered admission never waits for a sink write: it publishes one coalesced eligibility notification.
`Lifecycle::channel()` grants execution only through explicit events. Use it for response-bound hosts;
25 buffered items remain retained until a completion event, explicit flush, or shutdown.
`Lifecycle::tokio()` permits work between responses in persistent processes. Its single driver checks
eligibility after admission and through the writer's optional `.periodic_flush(interval)` timer.
A custom `LifecycleEvents` implementation opts into this permission with
`can_flush_between_responses`; the default is false. Periodic configuration with an event-bound
source is rejected at `start`, before claiming the one lifetime driver slot. Starting requires an
active Tokio runtime. Retain the guard until shutdown; source closure or cancellation makes it inactive.
Host triggers coalesce in bounded storage, with explicit flush above ordinary checks and shutdown
above all other work. Repeated shutdown events shorten the same active deadline, including while
sink I/O is pending. The driver observes retained ownership before waiting for that I/O to finish;
unconfirmed effects remain recoverable under the same sealed identity. Admission notifications and
timer ticks evaluate current eligible work within a bounded turn; only real response completion
uses a response watermark. This prevents racing additions from being stranded below that watermark.
Dropping a guard before shutdown emits `GuardDroppedBeforeShutdown`, without inventing an item
count. Use a drain report for known or unknown retained ownership.
Cloud lifecycle notifications are bounded opportunities; forced termination cannot guarantee a final drain.

Completed admission receipts keep at most 4,096 identities in completion order. Active or quarantined
identities remain retained with their work and do not consume this completed cache. Byte pressure can
reclaim completed receipts before that count limit. Eviction ends local admission deduplication for
that identity; there is no minimum time horizon. Destination idempotency and its retention policy
must cover later retries.

`BufferStats::bytes` includes modeled open, sealed, receipt, completion, and quarantine metadata,
including unused lifecycle reservations on open records. It reports capacity charges, not just payload
bytes. Completed-cache bytes remain charged until reclaimed atomically. Sealed entries reserve every
possible completion marker before delivery, so partial progress and quarantine do not grow that charge.
`BufferSnapshot::reclaimable_bytes` identifies the completed portion for admission preflight.
Charges use logical byte lengths, inline representation sizes, and a fixed map-entry allowance.
They do not measure process RSS, allocator spare capacity, or a larger allocation behind a caller's
byte slice. Local new-write staging is serialized and bounded by observed protected retention plus
unresolved dispatch credits. Completed receipt-cache charges may be reclaimed during append. A
same-ID retry borrows logical credit for that identity while checking its encoding; this does not
bound temporary duplicate allocations or total client memory across separate writer instances.
Decoded values, codec internals, and transport copies need their own physical headroom. Settlement
rejects completion identities outside the sealed batch before changing retained ownership.

Reducing capacity below protected retained ownership returns `InsufficientRecoveryCapacity` before
constructing another item. Increasing preparation requirements beyond persisted per-record credits
returns `InsufficientPreparationCredit` before calling preparation. Both appear as configuration
errors, preserve canonical records, and stop automatic waiting. Restore the previous configuration,
drain its work, then apply the new settings. Completed receipt-cache bytes remain reclaimable.
The crate cannot recreate a previous caller closure or migrate its effects automatically.

Advanced `WriteBatch` implementations default to `PreparationLayout::Custom`. A strategy may declare
`Records` only when it returns unchanged canonical records; command output under that declaration
is rejected before delivery. Ordinary builders and preparation closures need no layout setting.

The deterministic key-presence CAS test uses a disposable Redis-compatible endpoint supplied by
the test runner through `BUFFERED_WRITES_REDIS_TEST_URL`. Run it with
`cargo test -p buffered-writes --all-features --lib given_observed_absence_when_empty_key_appears -- --include-ignored`.
It creates UUID-scoped test keys, verifies that an empty key inserted after an absent read is
preserved, and removes those keys. It is ignored in ordinary package runs.

Incomplete partial responses use the same circuit and fallback policy as failed atomic writes.
Confirmed operations are checkpointed before retrying the remainder; missing outcomes stay unknown.
An outage that reaches the configured fallback age opens the circuit and switches to synchronous
mode even before the ordinary failure-count threshold. Queue handoff cannot itself restore buffered
mode. A successful optional probe only permits real canary writes; recovery still needs the configured
successful-write count and a low backlog. Probe cancellation preserves the original fenced batch.

`FlushReport::queue_error` reports failed or ambiguous fallback publication. Unconfirmed queue or
buffer acknowledgements never count as settled work. Retrying an ambiguous publication preserves the
original batch identity; consumers must deduplicate possible queue copies atomically at the sink.
A confirmed publish followed by an unknown buffer-settlement response ends that turn without another
mutation. Later inspection or lease recovery reconciles retained ownership.

Persisted future UTC timestamps have unknown age. Eligibility uses the conservative upper bound
`Duration::MAX`, shared by retention statistics and outage policy. A finite replay horizon quarantines
such a message as `UncertainReplayAge` before sink effects; it does not silently extend the replay
window. Normal in-process buffer eligibility also uses monotonic age. Distributed leases still rely
on the retention provider's clock and fencing contract; a shutdown report can remain unresolved.

Settlement carries a relative retry delay (defaulting to the configured retry base delay).
The provider derives its deadline and stores its scheduling UTC time. A clock earlier than that scheduling fact makes
unleased work immediately retryable; active leases retain their provider-time fencing semantics.

The built-in disk provider syncs every accepted mutation. It has no grouped-sync mode.
Recovery reads at most the configured journal limit plus one byte and rejects an oversized journal
without changing it. A corrupt journal remains the quarantine artifact; admission and compaction
stop until the operator resolves it. Reopening does not append duplicate quarantine copies.
`compact_now()` is a blocking maintenance operation for an explicitly scheduled maintenance window;
ordinary writes compact automatically when journal capacity requires it. `has_interior_corruption()`
is a redacted inspection fact for operator recovery decisions.

Valkey uses state/metadata format v6 with a shared UUID revision. One atomic protocol checks
noeviction, persistent key TTLs, bounded value lengths and matching revisions on every operation.
Commit also compares exact old bytes and verifies server-time lease expiry immediately before one
MSET. Metadata-only inspection checks the revision prefix without returning retained payloads.
Each value is at most 16 MiB; a full pair transfer can approach 32 MiB plus framing. Snapshot copying
is proportional to namespace capacity; no throughput claim follows from the default 25-item limit.

TLS and nonempty authentication are required by default. Use
`ValkeyCredentials::new(password).with_tls_ca_pem(pem_bytes)` for a private CA; this overrides the
normal public root set while preserving peer and hostname verification. Insecure URL fragments
and embedded URL credentials are rejected. Explicit plaintext configuration is intended for controlled
local testing. Recovery workers call `list_scopes(cursor, limit, deadline)` with their own bounded
execution window; repeat discovery cycles while concurrent writes can change the scope list.

A live provider rejects disappearance of an already observed state/metadata pair. A new client
cannot distinguish a never-used namespace from total retention loss, or detect a coherent old copy.
`RemoteValkey` acknowledges the remote operation; it does not certify AOF or replica persistence.
Asynchronous replication can lose acknowledged writes or revert lease generations on failover.
Destination idempotency protects repeat effects, but cannot reconstruct buffered writes that were
lost before delivery. Operators own retained persistence, primary endpoint routing and failover.
See [Valkey replication](https://valkey.io/topics/replication/) and
[persistence](https://valkey.io/topics/persistence/). WAIT or WAITAOF alone does not make the
service strongly consistent; see the [WAITAOF contract](https://valkey.io/commands/waitaof/).


Enable `sqs` for the SDK-free SQS outage spool. The production path uses common-owned credentials,
SigV4 and HTTP implementations; official AWS and Smithy libraries are permitted only in tests.
Use `QueueConfig::sqs(url).with_quarantine_url(other_url)` on the writer builder, or construct
`SqsQueue::try_new(config)` for a standalone replay worker. The default body ceiling is 1 MiB;
`with_max_envelope_bytes(bytes)` selects a smaller operator limit for both source and quarantine.
The measured body includes the complete sealed envelope with canonical and prepared representations.
JSON request escaping is transport overhead, not part of the SQS message-body quota. Expanded poison
records may exceed the queue limit; rejection preserves the source message for operator recovery.
See [SQS message quotas](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html).

AWS JSON requests use the service-root URI and preserve QueueUrl in the body. Endpoint overrides
select the signed HTTPS destination, including an explicitly configured proxy path.
Explicit clients must disable redirects and transparent POST retries. One caller deadline covers
signing, dispatch and bounded response reading. A failed or missing publication acknowledgement may
leave a copy on the queue; retry the same immutable batch. Quarantine publishes and validates its
acknowledgement before deleting source ownership. These are separate operations, so a crash can
produce duplicate quarantine records. No shared transaction or atomic handoff is claimed.

FIFO publications use the stable batch UUID as their deduplication ID and a bounded hash of namespace
and scope as their default group. A configured FIFO group must contain 1–128 printable ASCII bytes.
FIFO quarantine uses a hash of its exact record. FIFO deduplication lasts only five minutes; sink
idempotency remains mandatory for later retries. Visibility renewals round positive subsecond values
up to seconds and reject values above 12 hours. SQS can reject renewal earlier because its 12-hour
ceiling starts at the original receive request, not the most recent renewal.

The ignored `sqs_native` test creates disposable source/quarantine queues and removes them on exit.
Set `BUFFERED_WRITES_SQS_PROFILE` to an authenticated development AWS CLI profile and optionally
`BUFFERED_WRITES_SQS_REGION` (default `eu-central-1`). Run
`cargo test -p buffered-writes --features sqs --test sqs_native -- --include-ignored`.
AWS CLI credential export is test infrastructure only; credentials are held in memory and never logged.
Injected protocol tests do not establish live AWS or deployed lifecycle behavior.


Persistent hosts share `TokioLifecycle` and the writer's existing response, timer and shutdown paths.
See the [host example and deployment files](deployments/README.md). Enable `ec2` for
`SpotLifecycle::new(ImdsSpotSource::try_new()?)`; downstream metering users enable
`metrics-facade/buffered-ec2` and use its re-exports. Metadata discovery has one scheduled pending
poll across response completions, typed failures and explicit cancellation. It never installs a
competing signal handler or falls back to IMDSv1. Stop/terminate deadlines use the original action
time; hibernation, expired or unknown action time grants no invented drain window.


Classic Lambda uses an extension-owned writer and a function-side `LambdaExtensionClient` over
bounded authenticated loopback IPC. Enable `lambda`, or `metrics-facade/buffered-lambda` for its
re-exports. The function sends its completion marker after the Runtime API response acknowledgement;
INVOKE itself is not completion. `LambdaExtensionServer::run` owns registration, provider events,
IPC and final drain without detached workers. See the [Lambda integration and wire contract](deployments/lambda-extension.md).
Local TCP/HTTP and six separate-process fixtures pass. Both thin binaries link for ARM64 Linux and package as a function plus extension layer;
deployed Lambda verification remains pending.
