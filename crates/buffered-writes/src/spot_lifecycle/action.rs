use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::Deadline;

/// EC2 Spot interruption action categories reported by IMDSv2
/// `spot/instance-action`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpotActionKind {
    Terminate,
    Stop,
    Hibernate,
}

/// Parsed IMDSv2 `spot/instance-action` notice.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpotInstanceAction {
    pub action: SpotActionKind,
    #[serde(default)]
    pub time: Option<String>,
}

impl SpotInstanceAction {
    pub(super) fn shutdown_deadline(&self, maximum: Duration) -> Deadline {
        let anchor = Instant::now();
        let budget = match self.action {
            SpotActionKind::Hibernate => Duration::ZERO,
            SpotActionKind::Terminate | SpotActionKind::Stop => self
                .time
                .as_deref()
                .and_then(|time| chrono::DateTime::parse_from_rfc3339(time).ok())
                .and_then(|time| time.signed_duration_since(chrono::Utc::now()).to_std().ok())
                .unwrap_or(Duration::ZERO)
                .min(maximum),
        };
        Deadline::from_anchor(anchor, budget)
    }
}

impl std::fmt::Debug for SpotInstanceAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SpotInstanceAction")
            .field("action", &self.action)
            .field("has_action_time", &self.time.is_some())
            .finish()
    }
}
