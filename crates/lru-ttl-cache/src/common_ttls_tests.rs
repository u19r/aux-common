use std::time::Duration;

use crate::{
    CommonCacheTtl, CommonCacheTtlOverrides,
    constants::{
        COMMON_TTL_EXTRA_EXTRA_LONG, COMMON_TTL_EXTRA_LONG, COMMON_TTL_LONG, COMMON_TTL_SHORT,
        COMMON_TTL_STANDARD,
    },
};

#[test]
fn given_five_common_cache_ttl_buckets_when_resolving_defaults_then_durations_match_contract() {
    let buckets = [
        (CommonCacheTtl::Short, COMMON_TTL_SHORT),
        (CommonCacheTtl::Standard, COMMON_TTL_STANDARD),
        (CommonCacheTtl::Long, COMMON_TTL_LONG),
        (CommonCacheTtl::ExtraLong, COMMON_TTL_EXTRA_LONG),
        (CommonCacheTtl::ExtraExtraLong, COMMON_TTL_EXTRA_EXTRA_LONG),
    ];

    for (bucket, expected_duration) in buckets {
        assert_eq!(bucket.default_duration(), expected_duration);
    }
}

#[test]
fn given_default_overrides_when_resolving_each_bucket_then_defaults_are_preserved() {
    let overrides = CommonCacheTtlOverrides::default();

    let buckets = [
        CommonCacheTtl::Short,
        CommonCacheTtl::Standard,
        CommonCacheTtl::Long,
        CommonCacheTtl::ExtraLong,
        CommonCacheTtl::ExtraExtraLong,
    ];

    for bucket in buckets {
        assert_eq!(overrides.resolve(bucket), bucket.default_duration());
    }
}

#[test]
fn given_bucket_overrides_when_resolving_each_bucket_then_selected_values_replace_defaults() {
    let overrides = CommonCacheTtlOverrides::default()
        .with_override(CommonCacheTtl::Short, Duration::ZERO)
        .with_override(CommonCacheTtl::Standard, Duration::from_secs(7))
        .with_override(CommonCacheTtl::Long, Duration::from_secs(61))
        .with_override(CommonCacheTtl::ExtraLong, Duration::from_secs(301))
        .with_override(CommonCacheTtl::ExtraExtraLong, Duration::from_secs(1_801));

    assert_eq!(overrides.resolve(CommonCacheTtl::Short), Duration::ZERO);
    assert_eq!(
        overrides.resolve(CommonCacheTtl::Standard),
        Duration::from_secs(7)
    );
    assert_eq!(
        overrides.resolve(CommonCacheTtl::Long),
        Duration::from_secs(61)
    );
    assert_eq!(
        overrides.resolve(CommonCacheTtl::ExtraLong),
        Duration::from_secs(301)
    );
    assert_eq!(
        overrides.resolve(CommonCacheTtl::ExtraExtraLong),
        Duration::from_secs(1_801)
    );
}

#[test]
fn given_overrides_when_resolving_refresh_ttls_then_previous_bucket_is_used() {
    let overrides = CommonCacheTtlOverrides::default()
        .with_override(CommonCacheTtl::Short, Duration::from_secs(3))
        .with_override(CommonCacheTtl::Standard, Duration::from_secs(7))
        .with_override(CommonCacheTtl::Long, Duration::from_secs(61))
        .with_override(CommonCacheTtl::ExtraLong, Duration::from_secs(301));

    assert_eq!(overrides.refresh_ttl(CommonCacheTtl::Short), None);
    assert_eq!(
        overrides.refresh_ttl(CommonCacheTtl::Standard),
        Some(Duration::from_secs(3))
    );
    assert_eq!(
        overrides.refresh_ttl(CommonCacheTtl::Long),
        Some(Duration::from_secs(7))
    );
    assert_eq!(
        overrides.refresh_ttl(CommonCacheTtl::ExtraLong),
        Some(Duration::from_secs(61))
    );
    assert_eq!(
        overrides.refresh_ttl(CommonCacheTtl::ExtraExtraLong),
        Some(Duration::from_secs(301))
    );
}

#[test]
fn given_refresh_disabled_when_resolving_ttls_then_all_buckets_return_none() {
    let overrides = CommonCacheTtlOverrides {
        enable_background_refresh: false,
        ..CommonCacheTtlOverrides::default()
    };

    let buckets = [
        CommonCacheTtl::Short,
        CommonCacheTtl::Standard,
        CommonCacheTtl::Long,
        CommonCacheTtl::ExtraLong,
        CommonCacheTtl::ExtraExtraLong,
    ];

    for bucket in buckets {
        assert_eq!(overrides.refresh_ttl(bucket), None);
    }
}
