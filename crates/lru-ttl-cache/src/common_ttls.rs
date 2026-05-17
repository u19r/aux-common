use std::time::Duration;

use crate::constants::{
    COMMON_TTL_COLD, COMMON_TTL_EXTENDED, COMMON_TTL_EXTRA_LONG, COMMON_TTL_LONG,
    COMMON_TTL_REGULAR, COMMON_TTL_SHORT, COMMON_TTL_STATIC, COMMON_TTL_VERY_SHORT,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonCacheTtl {
    VeryShort,
    Short,
    Regular,
    Long,
    ExtraLong,
    Extended,
    Cold,
    Static,
}

impl CommonCacheTtl {
    #[must_use]
    pub const fn default_duration(self) -> Duration {
        match self {
            Self::VeryShort => COMMON_TTL_VERY_SHORT,
            Self::Short => COMMON_TTL_SHORT,
            Self::Regular => COMMON_TTL_REGULAR,
            Self::Long => COMMON_TTL_LONG,
            Self::ExtraLong => COMMON_TTL_EXTRA_LONG,
            Self::Extended => COMMON_TTL_EXTENDED,
            Self::Cold => COMMON_TTL_COLD,
            Self::Static => COMMON_TTL_STATIC,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommonCacheTtlOverrides {
    pub enable_background_refresh: bool,
    pub very_short: Option<Duration>,
    pub short: Option<Duration>,
    pub regular: Option<Duration>,
    pub long: Option<Duration>,
    pub extra_long: Option<Duration>,
    pub extended: Option<Duration>,
    pub cold: Option<Duration>,
    pub static_ttl: Option<Duration>,
}

impl Default for CommonCacheTtlOverrides {
    fn default() -> Self {
        Self {
            enable_background_refresh: true,
            very_short: None,
            short: None,
            regular: None,
            long: None,
            extra_long: None,
            extended: None,
            cold: None,
            static_ttl: None,
        }
    }
}

impl CommonCacheTtlOverrides {
    #[must_use]
    pub fn refresh_ttl(&self, key: CommonCacheTtl) -> Option<Duration> {
        if self.enable_background_refresh {
            Some(self.resolve(key))
        } else {
            None
        }
    }

    #[must_use]
    pub fn resolve(&self, key: CommonCacheTtl) -> Duration {
        match key {
            CommonCacheTtl::VeryShort => self.very_short,
            CommonCacheTtl::Short => self.short,
            CommonCacheTtl::Regular => self.regular,
            CommonCacheTtl::Long => self.long,
            CommonCacheTtl::ExtraLong => self.extra_long,
            CommonCacheTtl::Extended => self.extended,
            CommonCacheTtl::Cold => self.cold,
            CommonCacheTtl::Static => self.static_ttl,
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
            CommonCacheTtl::VeryShort => self.very_short = Some(ttl),
            CommonCacheTtl::Short => self.short = Some(ttl),
            CommonCacheTtl::Regular => self.regular = Some(ttl),
            CommonCacheTtl::Long => self.long = Some(ttl),
            CommonCacheTtl::ExtraLong => self.extra_long = Some(ttl),
            CommonCacheTtl::Extended => self.extended = Some(ttl),
            CommonCacheTtl::Cold => self.cold = Some(ttl),
            CommonCacheTtl::Static => self.static_ttl = Some(ttl),
        }
    }
}
