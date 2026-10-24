use tokio::sync::watch;

use crate::RefreshDemand;

/// Shared, one-way demand promotion across nested cache and source cohorts.
/// Cold demand never becomes background again. Foreground state allocates
/// nothing.
#[derive(Clone)]
pub struct RefreshPriority(Option<watch::Sender<bool>>);

tokio::task_local! {
    static CURRENT_PRIORITY: RefreshPriority;
}

impl RefreshPriority {
    pub fn current() -> Self {
        CURRENT_PRIORITY
            .try_with(Clone::clone)
            .unwrap_or(Self(None))
    }

    pub fn demand(&self) -> RefreshDemand {
        if self.0.as_ref().is_some_and(|priority| !*priority.borrow()) {
            RefreshDemand::Background
        } else {
            RefreshDemand::Cold
        }
    }

    pub(crate) fn promote_cold(&self) {
        if let Some(priority) = &self.0 {
            priority.send_replace(true);
        }
    }

    /// Wakes source admission when any outer cache/source cohort gets cold
    /// demand.
    pub async fn promoted(&self) {
        if let Some(priority) = &self.0 {
            let mut receiver = priority.subscribe();
            let _ = receiver.wait_for(|cold| *cold).await;
        }
    }

    pub(super) async fn scope<F: std::future::Future>(
        demand: RefreshDemand,
        future: F,
    ) -> F::Output {
        let priority = match demand {
            RefreshDemand::Cold => Self(None),
            RefreshDemand::Background => Self(Some(watch::channel(false).0)),
        };
        CURRENT_PRIORITY.scope(priority, future).await
    }
}
