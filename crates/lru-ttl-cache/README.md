# lru-ttl-cache

## Purpose

The `lru-ttl-cache` crate provides reusable in-memory caches with time-to-live expiration and optional async refresh behavior. It is designed to reduce duplicated cache code across services while preserving predictable expiration and concurrency behavior.

## What Is Non-Standard Here

The crate supports both plain TTL cache usage and fetching cache usage that can refresh stale entries asynchronously after a configurable threshold. This split behavior requires careful understanding of when requests block on fetch versus when background refresh is spawned.

## Architecture and Data Flow

`LruTtlCache` and `FetchingLruTtlCache` in `crates/lru-ttl-cache/src/cache.rs` share a `CacheCore` implemented in `crates/lru-ttl-cache/src/core.rs`. The core uses a mutex-protected map with per-entry access ordering. Cache hits update entry metadata without cloning keys. `CacheConfig` and `FetchingCacheConfig` define capacity/TTL/refresh settings. For fetching mode, cache lookups can return cached values immediately while scheduling background refresh work via `tokio::spawn` when refresh TTL has elapsed.

## Critical Invariants

- Cache capacity must never collapse below 1.
- Expired entries must be treated as misses and removed.
- Refresh tasks should never spawn concurrently for the same entry while one refresh is in flight.
- Fetching mode must store only successful fetch values and clear entries when fetch returns `None`.
- Cache stats must reflect hits/misses/refresh outcomes accurately.
- Fetching cache must never panic on fetch errors; errors should flow through result paths.

## Workflows

### Cache-Aside Fetch and Store

Fetching mode uses a cache-aside flow where misses trigger async fetch, and successful values are inserted with fresh timestamps. This workflow intentionally decouples fetch logic from storage internals.

### Background Refresh-on-Read

When refresh TTL is configured, stale-but-not-expired entries can be served immediately while a background refresh task updates the value. This preserves low-latency reads while keeping data fresh.

## Error Semantics and Failure Modes

Plain cache APIs are infallible for in-memory operations. Fetching cache APIs propagate caller-defined fetch errors, and refresh errors are recorded in stats and tracing warnings without crashing the cache path.

## Observability and Debugging

Use `CacheStats` (`hits`, `misses`, `refreshes`, `refresh_errors`) to evaluate cache behavior. Debug public API and refresh flow in `crates/lru-ttl-cache/src/cache.rs`, entry lifecycle and eviction in `crates/lru-ttl-cache/src/core.rs`, and configuration wiring in `crates/lru-ttl-cache/src/config.rs`.

## Known Limits and Technical Debt

Background refresh currently relies on task spawning per refresh trigger, which is simple but can require tuning in very high-cardinality workloads.
