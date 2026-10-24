# bg-jobs-conformance

Executable proof helpers for a consumer-provided
`bg_jobs::JobStore`. Checks ordered reads, bounded range paging, checked atomic commits,
exact commit-operation replay, mismatched operation-ID rejection, conflicts, ambiguous outcomes,
bounded repair planning, and representative operation counts.

Contains test/reference infrastructure only. `FakeStore`, `FaultStore`, `CountingStore`, and
`StoreModel` are test-only.

Enable the `test-support` feature on `bg-jobs` when using the reference store in a conformance
harness; production adapters should implement `bg_jobs::JobStore` directly.

## Run a basic proof

The runners are async so the consuming repository can use its own runtime:

The compile-checked [`examples/quickstart.rs`](examples/quickstart.rs) keeps the async runner
shape without selecting a runtime.

```rust
use bg_jobs::test_support::FakeStore;
use bg_jobs_conformance::{ConformanceConfig, run_basic};

async fn prove_store() -> Result<(), Box<dyn std::error::Error>> {
    let store = FakeStore::distributed();
    let report = run_basic(&store, &ConformanceConfig::default()).await?;
    assert!(report.assertions > 0);
    Ok(())
}
```

`ConformanceConfig::default()` allocates a process-unique key prefix, so a run does not delete
fixtures left by another in-process run. When proofs share a backend across processes, pass an
externally unique prefix with `ConformanceConfig::try_new` instead.
