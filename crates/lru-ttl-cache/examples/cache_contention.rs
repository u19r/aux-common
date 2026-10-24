//! Equal offered work for cache hits with replacement, expiry, eviction, and
//! refresh.

use std::{
    error::Error,
    hint::black_box,
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use lru_ttl_cache::{CacheConfig, FetchingLruTtlCache, arc_fetch_fn};
use tokio::sync::Semaphore;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone, Copy)]
struct ProbeInput {
    capacity: usize,
    workers: usize,
    hot_keys: usize,
    rounds: usize,
    lookups_per_round: usize,
}

struct RoundBarriers {
    start: Barrier,
    finish: Barrier,
    refresh: Semaphore,
}

struct MixedProbe {
    input: ProbeInput,
    cache: FetchingLruTtlCache<u64, u64, ()>,
    barriers: Arc<RoundBarriers>,
    refresh_calls: Arc<AtomicU64>,
}

struct WorkerSamples {
    nanos: Vec<u64>,
    hits: Vec<bool>,
}

struct WriterSamples {
    round_nanos: Vec<u64>,
    expiry_misses: usize,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    measure_clock();
    for capacity in [128, 10_000] {
        for workers in [8, 32] {
            MixedProbe::new(ProbeInput::new(capacity, workers))
                .measure_workload()
                .await?;
        }
    }
    Ok(())
}

impl ProbeInput {
    fn new(capacity: usize, workers: usize) -> Self {
        Self {
            capacity,
            workers,
            hot_keys: capacity / 2,
            rounds: 16,
            lookups_per_round: 128,
        }
    }
}

fn make_refresh(
    barriers: Arc<RoundBarriers>,
    calls: Arc<AtomicU64>,
) -> lru_ttl_cache::FetchFn<u64, u64, ()> {
    arc_fetch_fn(move |key: u64| {
        let barriers = Arc::clone(&barriers);
        let calls = Arc::clone(&calls);
        async move {
            barriers
                .refresh
                .acquire()
                .await
                .expect("refresh permit")
                .forget();
            let generation = calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok::<_, ()>(Some((generation << 32) | key))
        }
    })
}

impl MixedProbe {
    fn new(input: ProbeInput) -> Self {
        let barriers = Arc::new(RoundBarriers {
            start: Barrier::new(input.workers + 2),
            finish: Barrier::new(input.workers + 2),
            refresh: Semaphore::new(0),
        });
        let refresh_calls = Arc::new(AtomicU64::new(0));
        let fetch = make_refresh(Arc::clone(&barriers), Arc::clone(&refresh_calls));
        let cache = FetchingLruTtlCache::new(
            CacheConfig::new()
                .with_capacity(input.capacity)
                .with_ttl(Duration::from_millis(250))
                .with_fetch(fetch)
                .with_refresh_ttl(Duration::from_millis(1), |_| 0),
        );
        for key in 0..input.capacity as u64 {
            cache.insert(key, key);
        }
        Self {
            input,
            cache,
            barriers,
            refresh_calls,
        }
    }

    async fn measure_workload(self) -> Result<()> {
        let readers: Vec<_> = (0..self.input.workers)
            .map(|worker| self.spawn_reader(worker))
            .collect();
        let writer = self.spawn_writer();
        let started = Instant::now();
        let drain_reads = self.measure_rounds().await?;
        let elapsed = started.elapsed().as_nanos();
        let samples = readers
            .into_iter()
            .map(|reader| reader.join().map_err(|_| "reader panicked".into()))
            .collect::<Result<Vec<_>>>()?;
        let writer = writer.join().map_err(|_| "writer panicked")?;
        self.emit_samples(samples, writer, (elapsed, drain_reads));
        Ok(())
    }

    async fn measure_rounds(&self) -> Result<usize> {
        let mut drain_reads = 0;
        for round in 0..self.input.rounds {
            if round == self.input.rounds / 2 {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            for key in 0..self.input.hot_keys as u64 {
                self.cache.insert(key, key);
            }
            tokio::time::sleep(Duration::from_millis(3)).await;
            assert_eq!(Some(0), self.cache.cached(&0), "refresh entry must be live");
            self.barriers.start.wait();
            self.barriers.finish.wait();
            drain_reads += self.await_refresh(round).await?;
        }
        assert_eq!(
            self.input.rounds as u64,
            self.refresh_calls.load(Ordering::SeqCst)
        );
        Ok(drain_reads)
    }

    async fn await_refresh(&self, round: usize) -> Result<usize> {
        let expected = (round as u64 + 1) << 32;
        tokio::time::timeout(Duration::from_secs(1), async {
            let mut polls = 0;
            loop {
                polls += 1;
                if self.cache.peek(&0) == Some(expected) {
                    return polls;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| "refresh did not publish before drain deadline".into())
    }

    fn spawn_reader(&self, worker: usize) -> JoinHandle<WorkerSamples> {
        let input = self.input;
        let cache = self.cache.clone();
        let barriers = Arc::clone(&self.barriers);
        std::thread::spawn(move || {
            let mut samples = WorkerSamples {
                nanos: Vec::with_capacity(input.rounds * input.lookups_per_round),
                hits: Vec::with_capacity(input.rounds * input.lookups_per_round),
            };
            for _ in 0..input.rounds {
                barriers.start.wait();
                for lookup in 0..input.lookups_per_round {
                    let key = ((worker * input.lookups_per_round + lookup) % input.hot_keys) as u64;
                    let started = Instant::now();
                    let value = black_box(cache.peek(black_box(&key)));
                    samples.nanos.push(started.elapsed().as_nanos() as u64);
                    samples.hits.push(value.is_some());
                    if let Some(value) = value {
                        assert_eq!(key, value & u32::MAX as u64);
                    }
                }
                barriers.finish.wait();
            }
            samples
        })
    }

    fn spawn_writer(&self) -> JoinHandle<WriterSamples> {
        let input = self.input;
        let cache = self.cache.clone();
        let barriers = Arc::clone(&self.barriers);
        std::thread::spawn(move || {
            let mut samples = WriterSamples {
                round_nanos: Vec::new(),
                expiry_misses: 0,
            };
            for round in 0..input.rounds {
                barriers.start.wait();
                let started = Instant::now();
                barriers.refresh.add_permits(1);
                samples.expiry_misses += apply_mutations(&cache, input, round);
                samples
                    .round_nanos
                    .push(started.elapsed().as_nanos() as u64);
                barriers.finish.wait();
            }
            samples
        })
    }

    fn validate_counts(
        &self,
        reader_calls: usize,
        drain_reads: usize,
    ) -> lru_ttl_cache::CacheStats {
        let stats = self.cache.stats();
        assert_eq!(
            stats.hits + stats.misses,
            (reader_calls + self.input.rounds * 3 + drain_reads) as u64
        );
        assert_eq!(stats.refreshes, self.input.rounds as u64);
        assert_eq!(stats.refresh_errors, 0);
        stats
    }

    fn emit_samples(
        &self,
        samples: Vec<WorkerSamples>,
        writer: WriterSamples,
        timing: (u128, usize),
    ) {
        let mut all: Vec<_> = samples
            .iter()
            .flat_map(|sample| sample.nanos.iter().copied())
            .collect();
        all.sort_unstable();
        let mut hit_latencies: Vec<_> = samples
            .iter()
            .flat_map(|sample| {
                sample
                    .nanos
                    .iter()
                    .zip(&sample.hits)
                    .filter_map(|(nanos, hit)| hit.then_some(*nanos))
            })
            .collect();
        hit_latencies.sort_unstable();
        assert!(!hit_latencies.is_empty());
        let stats = self.validate_counts(all.len(), timing.1);
        let raw: Vec<_> = samples.iter().map(|sample| &sample.nanos).collect();
        let hits: Vec<_> = samples.iter().map(|sample| &sample.hits).collect();
        let report = serde_json::json!({
            "case": "mixed", "capacity": self.input.capacity, "workers": self.input.workers,
            "rounds": self.input.rounds, "lookups": all.len(), "hits": hit_latencies.len(),
            "misses": all.len() - hit_latencies.len(), "refresh_fetches": stats.refreshes,
            "initial_insertions": self.input.capacity, "writer_calls": self.input.rounds * 10,
            "round_setup_insertions": self.input.rounds * self.input.hot_keys,
            "drain_reads": timing.1, "expiry_misses": writer.expiry_misses,
            "all_p50_ns": read_percentile(&all, 50), "all_p95_ns": read_percentile(&all, 95),
            "all_p99_ns": read_percentile(&all, 99), "all_max_ns": all.last().unwrap(),
            "hit_p99_ns": read_percentile(&hit_latencies, 99),
            "wall_including_round_setup_ns": timing.0, "writer_round_ns": writer.round_nanos,
            "samples_ns_by_worker": raw, "is_hit_by_worker": hits
        });
        println!("{report}");
    }
}

fn apply_mutations(
    cache: &FetchingLruTtlCache<u64, u64, ()>,
    input: ProbeInput,
    round: usize,
) -> usize {
    let mut expiry_misses = 0;
    for operation in 0..8 {
        let hot = (1 + round % (input.hot_keys - 1)) as u64;
        match operation % 4 {
            0 => {
                let key = (input.capacity + round * 8 + operation) as u64;
                cache.insert(key, key);
            }
            1 => {
                cache.insert(hot, hot);
            }
            2 => {
                cache.remove(&hot);
                cache.insert(hot, hot);
            }
            3 => {
                expiry_misses += usize::from(cache.peek(&(input.capacity as u64 - 1)).is_none());
            }
            _ => unreachable!(),
        }
    }
    expiry_misses
}

fn read_percentile(sorted: &[u64], percentile: usize) -> u64 {
    sorted[(sorted.len() - 1) * percentile / 100]
}

fn measure_clock() {
    let mut nanos = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        let started = Instant::now();
        nanos.push(started.elapsed().as_nanos() as u64);
    }
    nanos.sort_unstable();
    println!(
        "{{\"case\":\"clock_calibration\",\"samples\":{},\"p50_ns\":{},\"p99_ns\":{}}}",
        nanos.len(),
        read_percentile(&nanos, 50),
        read_percentile(&nanos, 99)
    );
}
