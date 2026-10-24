use std::time::Duration;

use crate::constants::{
    COMMON_TTL_EXTRA_EXTRA_LONG, COMMON_TTL_EXTRA_LONG, COMMON_TTL_LONG, COMMON_TTL_SHORT,
    COMMON_TTL_STANDARD,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonCacheTtl {
    Short,
    Standard,
    Long,
    ExtraLong,
    ExtraExtraLong,
}

impl CommonCacheTtl {
    #[must_use]
    pub const fn default_duration(self) -> Duration {
        match self {
            Self::Short => COMMON_TTL_SHORT,
            Self::Standard => COMMON_TTL_STANDARD,
            Self::Long => COMMON_TTL_LONG,
            Self::ExtraLong => COMMON_TTL_EXTRA_LONG,
            Self::ExtraExtraLong => COMMON_TTL_EXTRA_EXTRA_LONG,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommonCacheTtlOverrides {
    pub enable_background_refresh: bool,
    pub short: Option<Duration>,
    pub standard: Option<Duration>,
    pub long: Option<Duration>,
    pub extra_long: Option<Duration>,
    pub extra_extra_long: Option<Duration>,
}

impl Default for CommonCacheTtlOverrides {
    fn default() -> Self {
        Self {
            enable_background_refresh: true,
            short: None,
            standard: None,
            long: None,
            extra_long: None,
            extra_extra_long: None,
        }
    }
}

impl CommonCacheTtlOverrides {
    #[must_use]
    pub fn refresh_ttl(&self, key: CommonCacheTtl) -> Option<Duration> {
        let refresh_key = match key {
            CommonCacheTtl::Short => return None,
            CommonCacheTtl::Standard => CommonCacheTtl::Short,
            CommonCacheTtl::Long => CommonCacheTtl::Standard,
            CommonCacheTtl::ExtraLong => CommonCacheTtl::Long,
            CommonCacheTtl::ExtraExtraLong => CommonCacheTtl::ExtraLong,
        };
        self.enable_background_refresh
            .then(|| self.resolve(refresh_key))
    }

    #[must_use]
    pub fn resolve(&self, key: CommonCacheTtl) -> Duration {
        match key {
            CommonCacheTtl::Short => self.short,
            CommonCacheTtl::Standard => self.standard,
            CommonCacheTtl::Long => self.long,
            CommonCacheTtl::ExtraLong => self.extra_long,
            CommonCacheTtl::ExtraExtraLong => self.extra_extra_long,
        }
        .unwrap_or_else(|| key.default_duration())
    }

    #[must_use]
    pub fn with_override(mut self, key: CommonCacheTtl, ttl: Duration) -> Self {
        self.set_override(key, ttl);
        self
    }

    pub fn set_override(&mut self, key: CommonCacheTtl, ttl: Duration) {
        match key {
            CommonCacheTtl::Short => self.short = Some(ttl),
            CommonCacheTtl::Standard => self.standard = Some(ttl),
            CommonCacheTtl::Long => self.long = Some(ttl),
            CommonCacheTtl::ExtraLong => self.extra_long = Some(ttl),
            CommonCacheTtl::ExtraExtraLong => self.extra_extra_long = Some(ttl),
        }
    }
}
