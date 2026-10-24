//! Reproducible public-API measurements; no database or application policy is
//! substituted.

use std::{
    error::Error,
    hint::black_box,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use lru_ttl_cache::{CacheConfig, FetchingLruTtlCache, LruTtlCache, arc_fetch_fn};

#[derive(Clone, Copy)]
enum FetchOutcome {
    Value,
    Missing,
    Error,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    for capacity in [128, 10_000] {
        measure_hits(capacity)?;
        measure_eviction(capacity);
    }
    for outcome in [
        FetchOutcome::Value,
        FetchOutcome::Missing,
        FetchOutcome::Error,
    ] {
        measure_singleflight(outcome).await?;
    }
    measure_refresh_expiry_overlap().await?;
    Ok(())
}

fn create_populated_cache(capacity: usize) -> LruTtlCache<u64, u64> {
    let cache = LruTtlCache::new(
        CacheConfig::new()
            .with_capacity(capacity)
            .with_ttl(Duration::from_secs(3600)),
    );
    for key in 0..capacity as u64 {
        cache.insert(key, key);
    }
    cache
}

fn measure_hits(capacity: usize) -> Result<(), Box<dyn Error>> {
    for workers in [1, 8, 32] {
        let cache = create_populated_cache(capacity);
        let started = Instant::now();
        run_hit_workers(&cache, capacity, workers)?;
        let elapsed = started.elapsed().as_nanos();
        println!(
            "{{\"case\":\"hit\",\"capacity\":{capacity},\"workers\":{workers},\"operations\":{},\"\
             elapsed_ns\":{elapsed},\"amortized_wall_ns_per_operation\":{}}}",
            workers * 100_000,
            elapsed as f64 / (workers * 100_000) as f64
        );
    }
    Ok(())
}

fn run_hit_workers(
    cache: &LruTtlCache<u64, u64>,
    capacity: usize,
    workers: usize,
) -> Result<(), Box<dyn Error>> {
    std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..workers)
            .map(|_| scope.spawn(|| read_cache_hits(cache.clone(), capacity)))
            .collect();
        for task in tasks {
            if task.join().is_err() {
                return Err("cache benchmark worker failed".into());
            }
        }
        Ok(())
    })
}

fn read_cache_hits(cache: LruTtlCache<u64, u64>, capacity: usize) {
    for iteration in 0..100_000_u64 {
        let _ = black_box(cache.get_ref(&(iteration % capacity as u64)));
    }
}

fn measure_eviction(capacity: usize) {
    let cache = create_populated_cache(capacity);
    let started = Instant::now();
    for key in capacity as u64..capacity as u64 + 1000 {
        cache.insert(key, key);
    }
    let elapsed = started.elapsed().as_nanos();
    println!(
        "{{\"case\":\"capacity_eviction\",\"capacity\":{capacity},\"operations\":1000,\"\
         elapsed_ns\":{elapsed},\"amortized_wall_ns_per_operation\":{}}}",
        elapsed as f64 / 1000.0
    );
}

async fn measure_singleflight(outcome: FetchOutcome) -> Result<(), Box<dyn Error>> {
    let fetches = Arc::new(AtomicU64::new(0));
    let cache = create_singleflight_cache(outcome, fetches.clone());
    let started = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..64 {
        let cache = cache.clone();
        tasks.spawn(async move { cache.get_or_fetch(&7).await });
    }
    while let Some(result) = tasks.join_next().await {
        let _ = black_box(result?);
    }
    let elapsed = started.elapsed().as_nanos();
    let concurrent_fetches = fetches.load(Ordering::Relaxed);
    let _ = black_box(cache.get_or_fetch(&7).await);
    let next_lookup_fetches = fetches.load(Ordering::Relaxed) - concurrent_fetches;
    let name = match outcome {
        FetchOutcome::Value => "value",
        FetchOutcome::Missing => "missing",
        FetchOutcome::Error => "error",
    };
    println!(
        "{{\"case\":\"singleflight_{name}\",\"callers\":64,\"fetches\":{concurrent_fetches},\"\
         next_lookup_fetches\":{next_lookup_fetches},\"elapsed_ns\":{elapsed}}}"
    );
    Ok(())
}

fn create_singleflight_cache(
    outcome: FetchOutcome,
    fetches: Arc<AtomicU64>,
) -> FetchingLruTtlCache<u64, u64, ()> {
    let fetch = arc_fetch_fn(move |key: u64| {
        let observed = fetches.clone();
        async move {
            observed.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(1)).await;
            match outcome {
                FetchOutcome::Value => Ok(Some(key)),
                FetchOutcome::Missing => Ok(None),
                FetchOutcome::Error => Err(()),
            }
        }
    });
    FetchingLruTtlCache::new(CacheConfig::new().with_capacity(128).with_fetch(fetch))
}

struct RefreshProbe {
    calls: AtomicU64,
    active: AtomicU64,
    max_active: AtomicU64,
    release: tokio::sync::Semaphore,
}

impl RefreshProbe {
    fn new() -> Self {
        Self {
            calls: AtomicU64::new(0),
            active: AtomicU64::new(0),
            max_active: AtomicU64::new(0),
            release: tokio::sync::Semaphore::new(0),
        }
    }

    async fn fetch(&self, key: u64) -> Result<Option<u64>, ()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let active = self.active.fetch_add(1, Ordering::Relaxed) + 1;
        self.max_active.fetch_max(active, Ordering::Relaxed);
        let result = self
            .release
            .acquire()
            .await
            .map(|_| Some(key))
            .map_err(|_| ());
        self.active.fetch_sub(1, Ordering::Relaxed);
        result
    }
}

async fn measure_refresh_expiry_overlap() -> Result<(), Box<dyn Error>> {
    let probe = Arc::new(RefreshProbe::new());
    let cache = create_refresh_cache(probe.clone());
    cache.insert(7, 7);
    tokio::time::sleep(Duration::from_millis(5)).await;
    let _ = black_box(cache.get_or_fetch(&7).await);
    wait_for_fetches(&probe, 1).await?;
    tokio::time::sleep(Duration::from_millis(40)).await;
    let cold = tokio::spawn(async move { cache.get_or_fetch(&7).await });
    let _ = wait_for_fetches(&probe, 2).await;
    let fetches = probe.calls.load(Ordering::Relaxed);
    let max_active = probe.max_active.load(Ordering::Relaxed);
    probe.release.add_permits(2);
    let _ = black_box(cold.await?);
    println!(
        "{{\"case\":\"refresh_expiry_overlap\",\"fetches\":{fetches},\"max_parallel_fetches\":\
         {max_active},\"ttl_ms\":30,\"refresh_ms\":2}}"
    );
    Ok(())
}

async fn wait_for_fetches(probe: &RefreshProbe, count: u64) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(1);
    while probe.calls.load(Ordering::Relaxed) < count {
        if Instant::now() >= deadline {
            return Err("controlled cache fetch did not start".into());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(())
}

fn create_refresh_cache(probe: Arc<RefreshProbe>) -> FetchingLruTtlCache<u64, u64, ()> {
    let fetch = arc_fetch_fn(move |key: u64| {
        let observed = probe.clone();
        async move { observed.fetch(key).await }
    });
    FetchingLruTtlCache::new(
        CacheConfig::new()
            .with_capacity(128)
            .with_ttl(Duration::from_millis(30))
            .with_fetch(fetch)
            .with_refresh_ttl(Duration::from_millis(2), |_| 0),
    )
}
