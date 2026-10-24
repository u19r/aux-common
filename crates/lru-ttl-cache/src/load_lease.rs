use tokio::sync::watch;

#[derive(Clone)]
pub(super) struct LoadLease(watch::Sender<bool>);

impl LoadLease {
    pub(super) fn new() -> Self {
        Self(watch::channel(false).0)
    }

    pub(super) fn is_same(&self, other: &Self) -> bool {
        self.0.same_channel(&other.0)
    }

    pub(super) fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    pub(super) fn cancel(&self) {
        self.0.send_replace(true);
    }

    pub(super) async fn cancelled(&self) {
        let mut receiver = self.0.subscribe();
        let _ = receiver.wait_for(|cancelled| *cancelled).await;
    }
}
