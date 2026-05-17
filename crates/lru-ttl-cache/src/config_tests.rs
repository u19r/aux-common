use std::time::Duration;

use crate::{CacheConfig, arc_fetch_fn};

#[test]
fn cache_config_uses_default_capacity_and_ttl_until_overridden() {
    let config = CacheConfig::<String, String>::new()
        .with_capacity(0)
        .with_ttl(Duration::from_secs(5));

    assert_eq!(
        format!("{config:?}"),
        "CacheConfig { capacity: 1, ttl: 5s }"
    );
}

#[test]
fn fetching_cache_config_stores_refresh_ttl_without_exposing_fetch_in_debug() {
    let fetch = arc_fetch_fn(|key: String| async move { Ok::<_, ()>(Some(key.len())) });
    let config = CacheConfig::<String, usize>::new()
        .with_capacity(10)
        .with_ttl(Duration::from_secs(60))
        .with_fetch(fetch)
        .with_refresh_ttl(Duration::from_secs(5));

    let debug = format!("{config:?}");
    assert!(debug.contains("FetchingCacheConfig"));
    assert!(debug.contains("capacity: 10"));
    assert!(debug.contains("ttl: 60s"));
    assert!(debug.contains("refresh_ttl: Some(5s)"));
    assert!(!debug.contains("fetch"));
}
