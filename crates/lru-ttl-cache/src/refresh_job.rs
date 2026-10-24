use std::{future::Future, panic::AssertUnwindSafe, pin::Pin};

use futures_util::FutureExt;
use tokio::sync::{OwnedSemaphorePermit, watch};

use crate::refresh_cancellation::RefreshCancellation;

pub(crate) struct RefreshJob {
    future: Pin<Box<dyn Future<Output = ()> + Send>>,
    cancellation: watch::Receiver<bool>,
    slots: OwnedSemaphorePermit,
    bytes: OwnedSemaphorePermit,
}

impl RefreshJob {
    pub(crate) fn new(
        future: impl Future<Output = ()> + Send + 'static,
        slots: OwnedSemaphorePermit,
        bytes: OwnedSemaphorePermit,
    ) -> (Self, RefreshCancellation) {
        let (sender, cancellation) = watch::channel(false);
        (
            Self {
                future: Box::pin(future),
                cancellation,
                slots,
                bytes,
            },
            RefreshCancellation(sender),
        )
    }

    pub(crate) async fn execute(self) {
        let Self {
            future,
            mut cancellation,
            slots: _slots,
            bytes: _bytes,
        } = self;
        // Provider and publication futures are destroyed before job admission
        // returns. A panicking callback must not remove a fixed worker.
        {
            let work =
                AssertUnwindSafe(crate::RefreshDemand::Background.scope(future)).catch_unwind();
            tokio::pin!(work);
            tokio::select! {
                biased;
                _ = cancellation.wait_for(|cancelled| *cancelled) => {},
                _ = &mut work => {},
            }
        }
    }
}
