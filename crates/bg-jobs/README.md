# bg-jobs

Runtime-neutral durable background-job engine. It owns validated job values and
codecs, lease/fence transitions, retries and dead letters, schedules and wake hints, fairness and
bounded batches, and the atomic ordered key/value contract used by those transitions.

## Start with a typed catalog

Register a handler once and keep its payload type behind the returned handle. The catalog and
handle are the routine API; raw records and handler definitions are reserved for adapters and
conformance code under `bg_jobs::test_support::raw` with the `test-support`
feature enabled.

The same setup is kept in the compile-checked [`examples/quickstart.rs`](examples/quickstart.rs)
file.

```rust
use std::num::NonZeroU16;

use bg_jobs::{
    EffectMode, FairnessPolicy, HandlerFuture, JobCatalog, JobHandler, JobKind, JobOutcome,
    JobSpec, QueueName, RetryPreset, RetrySelection,
};

struct ExampleHandler;

impl JobHandler for ExampleHandler {
    fn execute<'a>(
        &'a self,
        _context: bg_jobs::ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        Box::pin(async { Ok(JobOutcome::Cancelled) })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut catalog = JobCatalog::new();
    let handle = catalog.register(
        JobSpec::bytes(
            JobKind::try_new("example.job")?,
            NonZeroU16::MIN,
            QueueName::try_new("example")?,
            ExampleHandler,
        )
        .policy(
            EffectMode::Idempotent,
            FairnessPolicy::low_volume(),
            RetrySelection::Preset(RetryPreset::Interactive),
            std::time::Duration::from_secs(1),
        ),
    )?;

    assert_eq!(handle.kind().as_str(), "example.job");
    Ok(())
}
```

A library consumer supplies a production `JobStore` adapter, then passes the completed catalog to
the runtime facade in `bg-jobs-tokio`. The runtime owns the scheduler, clocks, bounded drives, and
shutdown loop. Do not expose raw `NewJob` or `HandlerDefinition` values from application code.

Tests that exercise deadlines or shutdown should use
`bg_jobs_tokio::test_support::{TestClock, TestProfile, runtime_builder}`. Inject the clock and
scheduler through `runtime_builder`, then advance them explicitly. This
keeps wake and deadline assertions deterministic without sleeping on wall-clock time or requiring a
particular async runtime.

`DriveBudget` validates static bounds and the Tokio runtime creates caller-clocked requests from
its monotonic clock, so consumers do not rebuild deadline arithmetic on every iteration.
`JobCatalog` composes handler registrations with optional stable seeds and provides an idempotent
seed operation; it deliberately contains no application roles, storage schema, routes, or
external-effect policy.

The optional `bg-jobs-tokio` crate supplies the `JobRuntime` facade. It keeps the core crate
runtime-neutral and hides `TokioWakeScheduler`, clock selection, bounded drive requests, and wake
delivery so Tokio consumers do not define the same timer bridge in each application.

## Production adapter boundary

`JobStore::get_many` is a required native batch/read-plan operation. It returns one result per input
key in the same order, including duplicate keys and missing values; implement it with the backend's
native facility rather than a loop over `get`. Empty input returns empty without backend I/O.
`StoreCapabilities::max_get_many_keys()` and `max_get_many_key_bytes()` bound each request; the byte
limit is the sum of input key bytes. A consumer using `aux-storage` should map this method to its
`ReadSequence` facility. This library deliberately has no production storage adapter.

`StoreTransaction` rejects repeated keys within its checks or within its mutations. One check and
one mutation may intentionally address the same key; that is the portable compare-and-swap form. A
transaction also carries a caller-owned `CommitOperationId`. An adapter binds the first accepted ID
to the exact checks and mutations, replays its established `Committed` or `Conflict` result for an
exact retry, and rejects reuse with different content without applying it. This identity belongs to
the logical store commit, not to one HTTP request or a digest of the transaction bytes.

After a commit has been dispatched, an ambiguous timeout or transport loss is
`Ok(CommitOutcome::Unknown)`. `Err` means the adapter knows the transaction did not apply. Retry the
same transaction with the same commit operation ID, or perform operation-specific reconciliation;
never invent a new ID and retry blindly. A native adapter may implement this contract with its
backend transaction ledger, while a separate-process adapter carries the ID unchanged across its
client/server protocol.

Only a consumer can prove a `Distributed` adapter: its backend-native contention tests must prove
one winner, one conflict, and no partial effects across the processes or nodes that use the store.
The fake/reference stores and conformance helpers are test infrastructure, not that proof and not
deployment components. The reusable [`bg-jobs-conformance`](../bg-jobs-conformance/README.md) suite
checks the portable contract but cannot certify backend contention. The consuming application also
owns handler registration, routes, payload migration, and runtime integration; this crate does not
replace those jobs by itself.

## Ownership and review

`JobStore` supplies ordered reads and atomic storage outcomes; `JobSystem` owns lifecycle, retry,
fairness, cancellation, and other state policy. Keep those business decisions out of adapters and
repository helpers. Public reports may expose passive fields, while secret-bearing or validated
mutable values keep private fields and enforce their invariants at construction.

Focused unit tests and the Cucumber workflows are the implementation-review evidence for this crate.
They do not replace consumer-owned backend contention tests, runtime integration, or production
adapter validation.

## Limits and semantics

| Resource                     |                                                           Limit |
| ---------------------------- | --------------------------------------------------------------: |
| Inline payload               |                                         972,800 bytes (950 KiB) |
| Checkpoint                   |                                           65,536 bytes (64 KiB) |
| Registered handler cost      |                                                1,024 cost units |
| HTTP or other backend values | The lower of the portable limit and reported backend capability |

Successful completion deletes the authoritative job state; callers own any audit or external-effect
record. The low-level `JobSystem::drive` operation is bounded and caller-clocked, while
`bg_jobs_tokio::JobRuntime::drive_once` supplies the clock and request construction for routine
Tokio consumers. Store and wake-scheduler futures must still enforce their own runtime deadlines;
operation-count budgets cannot interrupt an indefinitely pending backend call.
When a handler returns `JobOutcome::Continue`, the bounded checkpoint is persisted with the job and
is available to the next handler invocation through `ExecutionContext::checkpoint()`; the first
invocation receives `None`. `ExecutionContext::wall_now()` is the immutable wall-clock snapshot
captured when that context is constructed. It can be used directly as `not_before` for an
immediate continuation and does not advance while the handler runs. A committed continuation is a
successful workflow segment: it resets the retry attempt and age budget for the next segment while
preserving the execution identity, fencing high-water mark, and checkpoint. This permits one stable
controller job to perform a sequence of bounded scans without eventually exhausting failure retry
policy; an explicit job expiry remains a hard bound. Seed that controller at process startup with
`JobRuntime::ensure_seed` and a `JobSeed`: an existing matching job keeps its current schedule,
lifecycle state, and checkpoint, while the supplied `scheduled_at` is used only if the job is absent.
The low-level raw enqueue operation remains strict and rejects a replay whose original schedule has
changed; routine callers should use the typed catalog and runtime facade instead. It is available
only through the runtime adapter boundary, not through the routine facade.

Recurring poll handlers use `ExecutionContext::poll_checkpoint()` to resume their application
payload and `continue_poll()` to retain polling history in the checkpoint.
Mark selected eligible work with `record_poll_work_found()`. Activity survives intermediate pages
and resets the idle streak when the cycle ends. Empty cycles double the base delay up to five
minutes (or the base interval when longer), with deterministic 80–100 percent jitter; intermediate
pages keep their requested delay. `PollingJob` uses the same policy for idle passes. Failed passes
propagate to the normal retry policy instead of continuing indefinitely. Named retry presets default
to 180 consecutive attempts; explicit tighter limits and maximum-age bounds still apply. Exhausted
scheduled jobs use the existing durable dead-letter state and release scheduler capacity.

Handlers that must await a durable checkpoint before an external effect override
`JobHandler::execute_checkpointed`. The drive lends a privately constructed `JobExecution` for its
one mutable claim. Borrow its genuine `context()`, release that borrow, then await
`save_checkpoint(bytes)` before submitting the dependent effect. This uses the existing checkpoint
transaction and reconciliation; subsequent context reads and final completion see the updated
claim. The handle cannot be deserialized or constructed by the application. An error grants no
external-effect settlement or submission permission. Such a handler must reject context-only
`execute` invocation; the low-level immutable `execute_claimed` API cannot checkpoint. Existing
context-only handlers use the default method and retain their existing future.

Runtime lifecycle writes use the current wall time derived from the caller's monotonic clock.
Checkpoint context reads, checkpoint writes, and completion reject expired leases. A failed renewal
permanently revokes that claim's worker mutation authority, even if a later caller supplies an earlier
timestamp. Control-plane cancellation remains separate: the exact durable lease can still receive
an idempotent cancellation request and acknowledge its durable cancellation marker before expiry.
Acknowledgement verifies the current durable job, lease, fence, operation, and permit values.
If the worker disappears, the next drive or `expire_job` finalizes its cancellation after lease
expiry. That checked transaction preserves the terminal record and releases the matching lease,
cancellation marker, and owned permits without retrying the effect. Cancellation takes precedence
over retry or age exhaustion; malformed markers and ownership conflicts preserve durable state.
Scheduling and wake reports use fresh wall time, including work that becomes due during a handler.
The low-level `execute_claimed` operation requires current wall
time and a monotonic clock, rejects an expired claim, and caps execution at lease expiry; its caller
must supply fresh wall time when persisting the returned outcome.

## External effects and fencing

The job store fence prevents a stale worker from changing bg-jobs lifecycle state. It does not make
a separate analytics, repair, delete, backup, or other destination transaction atomic with the job
store. A pre-call or post-call authority check therefore cannot prevent a stale external commit.

For a fenced external effect, use `ExecutionContext::execution_id()` as the stable logical effect
identity and `ExecutionContext::fence()` as the monotonic authority epoch. The destination adapter
must atomically compare and advance that epoch in the same transaction that writes the effect,
checkpoint, and destination receipt. `owner()` is intentionally excluded because authority may move
between workers, and `JobId` is intentionally excluded because a job identifier may be reused or
redriven for another logical execution. Put any application business identifier in the validated
typed payload. `operation_id()` identifies the current local lifecycle operation and may rotate; use
it for correlation, not as the sole external idempotency key. `OperationReceipt` records local
lifecycle authority and is not an external-effect receipt. After an ambiguous local completion,
`reconcile` and `observe_lifecycle` establish the local result, while the consumer reconciles its
destination receipt independently.

With destination-side atomic fencing, consumers do not need a separate pending/activate lease
protocol. If a destination cannot atomically enforce the fence with its effect, keep a destination-
owned outbox, intent/activate, or equivalent safe handoff protocol; bg-jobs cannot manufacture that
atomicity across systems.

## Scheduler diagnostics

Install `metrics_observer::MetricsObserver` through the runtime observer. Prometheus exports:

| Metric | Labels and interpretation |
| --- | --- |
| `bg_jobs_due_delay_ms` | `queue`, `kind`: successful claim acknowledgement minus due time, clamped to zero; an initial zero due time is anchored to creation. |
| `bg_worker_run_once_ms` | `queue`, `kind`: elapsed attempt execution and settlement after claim acknowledgement, including errors and dropped futures. |
| `bg_jobs_running_count` | `queue`, `kind`: active claimed attempts; a drop guard balances starts and finishes. |
| `bg_worker_items_processed_total` | Continuations carry `queue`, `kind`, and `outcome="continued"`; they are progress, not terminal completions. |
| `bg_jobs_capacity_limited_total` | Closed `resource` labels identify rejected operation, discovery, payload, or fairness boundaries. These count boundary observations, not unique drives. |
| `bg_jobs_store_operations_reserved_total` | Worst-case scheduler operation reservations, including unused allowances; failed reservations add nothing. |
| `bg_jobs_store_operations_total` | Actual dispatched engine store calls by `operation`: `get`, `get_many`, `read_range`, `commit`; includes failed calls and enqueue/recovery/admin work outside drives. Empty bulk reads add nothing. |

Store calls are adapter calls, not physical SQL statements or billing-handler database calls.
The reservation and actual counters have different scopes: compare them over a controlled workload
with enqueue/admin activity accounted for, not as an exact per-drive utilization ratio. Capacity
observations do not change admission, fairness, deadlines, or retry policy. No job, tenant,
execution, payload, or storage key enters these metric labels.
