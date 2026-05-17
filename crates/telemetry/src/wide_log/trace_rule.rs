use std::str::FromStr;

use tracing::Level;

use super::field_security::SpanFields;
use crate::{config::TracingConfig, constants::FIELD_FEATURE};

#[derive(Clone, Debug)]
pub(crate) struct TraceRule {
    pub(crate) feature: String,
    pub(crate) level: Level,
}

impl TraceRule {
    pub(crate) fn from_config(tracing_cfg: &TracingConfig) -> Vec<Self> {
        tracing_cfg
            .traces
            .iter()
            .filter_map(|entry| {
                let feature = entry.feature.trim();
                if feature.is_empty() {
                    tracing::warn!(target = "wide_log", "trace rule skipped: empty feature");
                    return None;
                }
                let level = match Level::from_str(entry.log_level.trim()) {
                    Ok(level) => level,
                    Err(_) => {
                        tracing::warn!(
                            target = "wide_log",
                            feature,
                            log_level = entry.log_level.as_str(),
                            "trace rule skipped: invalid log level"
                        );
                        return None;
                    }
                };
                Some(Self {
                    feature: feature.to_string(),
                    level,
                })
            })
            .collect()
    }

    pub(crate) fn matches_event(
        &self,
        name: &'static str,
        level: Level,
        fields: &SpanFields,
    ) -> bool {
        if level > self.level {
            return false;
        }
        if name.starts_with(self.feature.as_str()) {
            return true;
        }
        fields
            .value_as_string(FIELD_FEATURE)
            .is_some_and(|value| value.starts_with(self.feature.as_str()))
    }
}
