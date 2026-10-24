use bg_jobs::test_support::FakeStore;
use bg_jobs_conformance::{ConformanceConfig, run_basic};

fn main() {
    let _ = prove_store;
}

async fn prove_store() -> Result<(), Box<dyn std::error::Error>> {
    let store = FakeStore::distributed();
    let report = run_basic(&store, &ConformanceConfig::default()).await?;
    assert!(report.assertions > 0);
    Ok(())
}
