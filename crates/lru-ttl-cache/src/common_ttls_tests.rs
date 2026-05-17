use std::time::Duration;

use crate::{
    CommonCacheTtl, CommonCacheTtlOverrides,
    constants::{COMMON_TTL_REGULAR, COMMON_TTL_STATIC, COMMON_TTL_VERY_SHORT},
};

#[test]
fn common_cache_ttl_resolves_documented_defaults() {
    assert_eq!(
        CommonCacheTtl::VeryShort.default_duration(),
        COMMON_TTL_VERY_SHORT
    );
    assert_eq!(
        CommonCacheTtl::Regular.default_duration(),
        COMMON_TTL_REGULAR
    );
    assert_eq!(CommonCacheTtl::Static.default_duration(), COMMON_TTL_STATIC);
}

#[test]
fn common_cache_ttl_overrides_replace_selected_defaults() {
    let overrides = CommonCacheTtlOverrides::default()
        .with_override(CommonCacheTtl::Short, Duration::from_secs(7));

    assert_eq!(
        overrides.resolve(CommonCacheTtl::Short),
        Duration::from_secs(7)
    );
    assert_eq!(
        overrides.resolve(CommonCacheTtl::VeryShort),
        CommonCacheTtl::VeryShort.default_duration()
    );
}

#[test]
fn common_cache_ttl_refresh_ttl_tracks_background_refresh_setting() {
    let mut overrides = CommonCacheTtlOverrides::default();
    overrides.set_override(CommonCacheTtl::Long, Duration::from_secs(30));

    assert_eq!(
        overrides.refresh_ttl(CommonCacheTtl::Long),
        Some(Duration::from_secs(30))
    );

    overrides.enable_background_refresh = false;
    assert_eq!(overrides.refresh_ttl(CommonCacheTtl::Long), None);
}
