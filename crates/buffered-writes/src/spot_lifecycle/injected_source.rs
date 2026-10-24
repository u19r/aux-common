use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use futures_util::future::BoxFuture;

use super::{action::SpotInstanceAction, spot_action_source::SpotActionSource};

#[derive(Default)]
struct InjectedSpotSourceState {
    notices: VecDeque<SpotInstanceAction>,
}

/// Controllable IMDSv2 Spot notice source for deterministic tests and
/// EventBridge forwarding.
#[derive(Clone, Default)]
pub struct InjectedSpotSource {
    state: Arc<Mutex<InjectedSpotSourceState>>,
}

impl std::fmt::Debug for InjectedSpotSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("InjectedSpotSource")
    }
}

impl InjectedSpotSource {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inject_notice(&self, notice: SpotInstanceAction) {
        if let Ok(mut guard) = self.state.lock() {
            guard.notices.push_back(notice);
        }
    }

    pub fn inject_json(&self, raw_json: &str) -> Result<(), serde_json::Error> {
        let notice: SpotInstanceAction = serde_json::from_str(raw_json)?;
        self.inject_notice(notice);
        Ok(())
    }
}

impl SpotActionSource for InjectedSpotSource {
    fn poll_spot_action(
        &self,
    ) -> BoxFuture<'static, Result<Option<SpotInstanceAction>, crate::LifecycleError>> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut state = state
                .lock()
                .map_err(|_| crate::LifecycleError::SourceUnavailable {
                    reason: "injected Spot source state is unavailable",
                })?;
            Ok(state.notices.pop_front())
        })
    }
}
