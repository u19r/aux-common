use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use futures_util::future::BoxFuture;

use crate::{
    engine::Engine,
    lifecycle::{LifecycleEvents, LifecycleTrigger},
    lifecycle_mailbox::LifecycleMailbox,
};

/// Owns the sole delivery task and keeps host deadlines observable during I/O.
pub(super) struct LifecycleDriver<T, L> {
    engine: Arc<Engine<T>>,
    lifecycle: L,
    cancelled: Arc<AtomicBool>,
    shutdown_completed: Arc<AtomicBool>,
}

impl<T: Send + Sync + 'static, L: LifecycleEvents> LifecycleDriver<T, L> {
    pub(super) fn new(
        engine: Arc<Engine<T>>,
        lifecycle: L,
        cancelled: Arc<AtomicBool>,
        shutdown_completed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            engine,
            lifecycle,
            cancelled,
            shutdown_completed,
        }
    }

    pub(super) async fn drive(self) {
        let background = self.lifecycle.can_flush_between_responses();
        let mut pending = LifecycleMailbox::default();
        let mut next = self.lifecycle.next_event();
        let mut timer = self.next_tick();
        let mut closed = false;
        loop {
            if self.cancelled.load(Ordering::Acquire) {
                break;
            }
            if let Some(trigger) = pending.take() {
                if self
                    .complete_work(trigger, &mut next, &mut pending, &mut closed)
                    .await
                {
                    self.shutdown_completed.store(true, Ordering::Release);
                    break;
                }
                continue;
            }
            if closed {
                break;
            }
            tokio::select! {
                event = &mut next => self.receive_event(event, &mut next, &mut pending, &mut closed),
                request = self.engine.flush_signal.notified(), if background => {
                    pending.push(request);
                }
                () = &mut timer, if background => {
                    pending.push(LifecycleTrigger::PeriodicTick);
                    timer = self.next_tick();
                }
            }
        }
        self.cancelled.store(true, Ordering::Release);
    }

    fn next_tick(&self) -> BoxFuture<'static, ()> {
        match self.engine.cfg.periodic_interval {
            Some(interval) => self.engine.cfg.clock.sleep(interval),
            None => Box::pin(std::future::pending()),
        }
    }

    async fn complete_work(
        &self,
        trigger: LifecycleTrigger,
        next: &mut BoxFuture<'static, Option<LifecycleTrigger>>,
        pending: &mut LifecycleMailbox,
        closed: &mut bool,
    ) -> bool {
        let mut shutdown = matches!(trigger, LifecycleTrigger::Shutdown { .. });
        let mut work: BoxFuture<'_, ()> = Box::pin(self.execute_trigger(trigger));
        loop {
            tokio::select! {
                () = &mut work => return shutdown,
                event = &mut *next, if !*closed => {
                    if let Some(LifecycleTrigger::Shutdown { deadline }) = event {
                        let _ = self.engine.begin_shutdown_drain(
                            deadline, self.engine.cfg.clock.now_instant(),
                        );
                        if !shutdown {
                            // Observe ownership now while the active turn settles or times out.
                            // Both futures share the shortened deadline and the turn lock.
                            let engine = &self.engine;
                            work = Box::pin(async move {
                                tokio::join!(work, engine.shutdown(deadline));
                            });
                            shutdown = true;
                        }
                    }
                    self.receive_event(event, next, pending, closed);
                }
            }
        }
    }

    fn receive_event(
        &self,
        event: Option<LifecycleTrigger>,
        next: &mut BoxFuture<'static, Option<LifecycleTrigger>>,
        pending: &mut LifecycleMailbox,
        closed: &mut bool,
    ) {
        match event {
            Some(trigger) => {
                pending.push(trigger);
                *next = self.lifecycle.next_event();
            }
            None => *closed = true,
        }
    }

    async fn execute_trigger(&self, trigger: LifecycleTrigger) {
        match trigger {
            LifecycleTrigger::ResponseCompleted => {
                let _ = self.engine.after_response().await;
            }
            LifecycleTrigger::PeriodicTick => {
                let _ = self.engine.flush_eligible_writes().await;
            }
            LifecycleTrigger::ExplicitFlush => {
                let _ = self.engine.flush_writes().await;
            }
            LifecycleTrigger::Shutdown { deadline } => {
                let _ = self.engine.shutdown(deadline).await;
            }
        }
    }
}
