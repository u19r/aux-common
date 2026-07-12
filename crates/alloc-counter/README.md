# alloc-counter

`alloc-counter` is a test-only allocation measurement harness for this workspace.

It provides:
- `#[alloc_counter::count_allocations]` attribute macro for tests (sync and async).
- A counting global allocator scoped by `AllocationGuard` windows.
- JSON output suitable for baseline vs experiment comparison.

## Add to a crate

In the target crate's `Cargo.toml`:

```toml
[dev-dependencies]
alloc-counter = { workspace = true }
```

## Use the attribute macro

```rust
#[test]
#[alloc_counter::count_allocations(label = "baseline")]
fn my_hot_path_tests() {
    // test body
}
```

```rust
#[tokio::test]
#[alloc_counter::count_allocations(label = "experiment")]
async fn my_async_hot_path_tests() {
    // test body
}
```

Run with output enabled:

```bash
cargo test -p <crate> <test_name> -- --nocapture --test-threads=1
```

## Persist JSON lines

Set `AUX_ALLOC_COUNTER_REPORT_PATH` to append one JSON object per report:

```bash
AUX_ALLOC_COUNTER_REPORT_PATH=/tmp/alloc.jsonl \
cargo test -p <crate> <test_name> -- --nocapture --test-threads=1
```

## JSON schema

Each report is a single-line JSON object:

```json
{
  "schema_version": 1,
  "event": "allocation_report",
  "module_path": "...",
  "test_name": "...",
  "file": "...",
  "line": 123,
  "label": "baseline",
  "allocation_count": 42,
  "allocated_bytes": 8192
}
```

## Notes

- Counts are process-local and include all heap allocations that occur while a guard is active.
- The harness serializes guard windows with a mutex so two guards cannot reset each other's
  counters. It cannot exclude allocations made by unrelated threads or async tasks while a guard
  is active.
- Async guards span every `.await`. Use them only in a dedicated test process with no background
  work, and avoid multi-thread runtimes when a current-thread runtime is sufficient.
- Enforced allocation budgets must run as one named test with `--test-threads=1`, for example:

  ```bash
  cargo test -p <crate> <exact_test_name> -- --exact --nocapture --test-threads=1
  ```

  Running an entire test binary with `--test-threads=1` serializes tests, but does not isolate
  allocations from threads or tasks started by the test itself.
