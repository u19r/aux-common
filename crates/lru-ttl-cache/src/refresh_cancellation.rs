use tokio::sync::watch;

pub(crate) struct RefreshCancellation(pub(crate) watch::Sender<bool>);

impl RefreshCancellation {
    pub(crate) fn abort(&self) {
        self.0.send_replace(true);
    }
}
