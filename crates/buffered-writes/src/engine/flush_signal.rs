use std::sync::Mutex;
#[cfg(feature = "tokio")]
use std::{future::poll_fn, task::Poll};

use futures_util::task::AtomicWaker;

use crate::{lifecycle::LifecycleTrigger, lifecycle_mailbox::LifecycleMailbox};

/// One pending eligibility or forced-capacity request. Publishing grants no
/// execution permission: the host or persistent driver must supply that window.
#[derive(Default)]
pub(crate) struct FlushSignal {
    pending: Mutex<LifecycleMailbox>,
    waiter: AtomicWaker,
}

impl FlushSignal {
    pub(crate) fn notify(&self) {
        self.publish_request(LifecycleTrigger::PeriodicTick);
    }

    pub(crate) fn request_capacity(&self) {
        self.publish_request(LifecycleTrigger::ExplicitFlush);
    }

    pub(crate) fn take_capacity_request(&self) -> bool {
        self.take_request() == Some(LifecycleTrigger::ExplicitFlush)
    }

    fn publish_request(&self, request: LifecycleTrigger) {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(request);
        self.waiter.wake();
    }

    fn take_request(&self) -> Option<LifecycleTrigger> {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    #[cfg(feature = "tokio")]
    pub(crate) async fn notified(&self) -> LifecycleTrigger {
        poll_fn(|context| {
            self.waiter.register(context.waker());
            self.take_request().map_or(Poll::Pending, Poll::Ready)
        })
        .await
    }
}
