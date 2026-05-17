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
- The harness serializes guard windows with a mutex to avoid cross-test contamination.
- Prefer `--test-threads=1` for stable comparisons.
