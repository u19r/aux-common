use std::{
    future::{Future, poll_fn},
    pin::pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Instant,
};

use futures_util::{future::BoxFuture, task::AtomicWaker};

use super::state::Engine;
use crate::{Clock, Deadline};

#[derive(Default)]
pub(super) struct DrainDeadline {
    deadline: Mutex<Option<Deadline>>,
    changes: super::wake::WakeSet,
}

impl DrainDeadline {
    pub(super) fn shorten(&self, requested: Deadline, now: Instant) -> Deadline {
        let deadline = {
            let mut current = self
                .deadline
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let deadline = current.map_or(requested, |current| current.shorten_to(requested, now));
            *current = Some(deadline);
            deadline
        };
        self.changes.wake_all();
        deadline
    }

    pub(super) fn constrain(&self, requested: Deadline, now: Instant) -> Deadline {
        let deadline = self
            .deadline
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        deadline.map_or(requested, |current| requested.shorten_to(current, now))
    }
}

struct PendingDeadline {
    requested: Deadline,
    waiter: Arc<AtomicWaker>,
    timer: Option<(Deadline, BoxFuture<'static, ()>)>,
}

impl PendingDeadline {
    fn new(requested: Deadline, waiter: Arc<AtomicWaker>) -> Self {
        Self {
            requested,
            waiter,
            timer: None,
        }
    }

    fn poll_expiry(
        &mut self,
        signal: &DrainDeadline,
        clock: &dyn Clock,
        context: &mut Context<'_>,
    ) -> Poll<()> {
        self.waiter.register(context.waker());
        let effective = signal.constrain(self.requested, clock.now_instant());
        let remaining = effective.remaining_at(clock.now_instant());
        if remaining.is_zero() {
            return Poll::Ready(());
        }
        if self
            .timer
            .as_ref()
            .is_none_or(|(current, _)| *current != effective)
        {
            self.timer = Some((effective, clock.sleep(remaining)));
        }
        match self.timer.as_mut() {
            Some((_, future)) => future.as_mut().poll(context),
            None => Poll::Pending,
        }
    }
}

impl<T: Send + Sync + 'static> Engine<T> {
    pub(super) async fn complete_engine_operation<F: Future>(
        &self,
        deadline: Deadline,
        operation: impl FnOnce() -> F,
    ) -> Option<F::Output> {
        let mut operation = pin!(async move { operation().await });
        let mut pending = None;
        poll_fn(|context| {
            let effective = self
                .drain_deadline
                .constrain(deadline, self.cfg.clock.now_instant());
            if effective.is_expired_at(self.cfg.clock.now_instant()) {
                return Poll::Ready(None);
            }
            if let Poll::Ready(output) = operation.as_mut().poll(context) {
                return Poll::Ready(Some(output));
            }
            let pending = pending.get_or_insert_with(|| {
                PendingDeadline::new(deadline, self.drain_deadline.changes.subscribe())
            });
            pending
                .poll_expiry(&self.drain_deadline, self.cfg.clock.as_ref(), context)
                .map(|()| None)
        })
        .await
    }
}
