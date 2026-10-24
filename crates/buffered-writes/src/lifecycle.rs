use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use futures_util::future::BoxFuture;

use crate::{
    configuration::Deadline,
    lifecycle_mailbox::LifecycleMailbox,
    observer::{WriteEvent, WriteObserver},
};

/// Trigger event emitted by a [`LifecycleEvents`] source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleTrigger {
    ResponseCompleted,
    PeriodicTick,
    ExplicitFlush,
    Shutdown { deadline: Deadline },
}

/// Host lifecycle event stream contract.
pub trait LifecycleEvents: Send + Sync + 'static {
    fn next_event(&self) -> BoxFuture<'static, Option<LifecycleTrigger>>;

    /// Allows admission notifications and the writer's optional timer to
    /// initiate work between responses. Leave false for hosts that can
    /// freeze execution. Events themselves grant a bounded execution window
    /// in either mode.
    fn can_flush_between_responses(&self) -> bool {
        false
    }
}

/// Entrypoint for constructing built-in lifecycle adapters.
pub struct Lifecycle;

impl Lifecycle {
    /// Creates a persistent-process adapter. The host forwards response and
    /// termination events; the writer owns the optional periodic timer.
    #[cfg(feature = "tokio")]
    #[must_use]
    pub fn tokio() -> crate::tokio_lifecycle::TokioLifecycle {
        crate::tokio_lifecycle::TokioLifecycle::new()
    }

    /// Creates an in-process controllable lifecycle stream for tests and custom
    /// hosts.
    #[must_use]
    pub fn channel() -> (LifecycleController, ChannelLifecycle) {
        let state = Arc::new(Mutex::new(ChannelState {
            events: LifecycleMailbox::default(),
            closed: false,
            #[cfg(feature = "tokio")]
            notify: Arc::new(tokio::sync::Notify::new()),
        }));
        (
            LifecycleController {
                state: Arc::clone(&state),
            },
            ChannelLifecycle { state },
        )
    }
}

struct ChannelState {
    events: LifecycleMailbox,
    closed: bool,
    #[cfg(feature = "tokio")]
    notify: Arc<tokio::sync::Notify>,
}

/// Controller for pushing [`LifecycleTrigger`] events into a
/// [`ChannelLifecycle`].
#[derive(Clone)]
pub struct LifecycleController {
    state: Arc<Mutex<ChannelState>>,
}

impl std::fmt::Debug for LifecycleController {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LifecycleController")
    }
}

impl LifecycleController {
    pub fn send(&self, trigger: LifecycleTrigger) {
        if let Ok(mut guard) = self.state.lock()
            && !guard.closed
        {
            guard.events.push(trigger);
            #[cfg(feature = "tokio")]
            guard.notify.notify_one();
        }
    }

    pub fn close(&self) {
        if let Ok(mut guard) = self.state.lock() {
            guard.closed = true;
            #[cfg(feature = "tokio")]
            guard.notify.notify_waiters();
        }
    }
}

/// Event stream paired with [`LifecycleController`].
#[derive(Clone)]
pub struct ChannelLifecycle {
    state: Arc<Mutex<ChannelState>>,
}

impl std::fmt::Debug for ChannelLifecycle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ChannelLifecycle")
    }
}

impl LifecycleEvents for ChannelLifecycle {
    fn next_event(&self) -> BoxFuture<'static, Option<LifecycleTrigger>> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            loop {
                #[cfg(feature = "tokio")]
                let notified = {
                    let Ok(mut guard) = state.lock() else {
                        return None;
                    };
                    let mut notified = Box::pin(Arc::clone(&guard.notify).notified_owned());
                    // Register under the state lock so close cannot fall
                    // between checking the terminal state and registering for
                    // its broadcast.
                    notified.as_mut().enable();
                    if let Some(event) = guard.events.take() {
                        return Some(event);
                    }
                    if guard.closed {
                        return None;
                    }
                    notified
                };
                #[cfg(feature = "tokio")]
                notified.await;

                #[cfg(not(feature = "tokio"))]
                {
                    let Ok(mut guard) = state.lock() else {
                        return None;
                    };
                    return guard.events.take();
                }
            }
        })
    }
}

pub(crate) struct RuntimeGuardInner {
    pub(crate) shutdown_completed: Arc<AtomicBool>,
    pub(crate) cancelled: Arc<AtomicBool>,
    pub(crate) observer: Arc<dyn WriteObserver>,
    #[cfg(feature = "tokio")]
    pub(crate) abort_handle: Option<tokio::task::AbortHandle>,
}

/// Owned guard returned by `BufferedWrites::start` and
/// `BufferedMetering::start`.
///
/// Keep this guard alive until explicit `shutdown(deadline)` finishes. Dropping
/// the guard before shutdown cancels the background driver task and emits a
/// lifecycle observation without running asynchronous work in `Drop`.
/// This observation has no item count: retained storage cannot be inspected
/// here.
#[must_use = "retain the RuntimeGuard until explicit shutdown completes"]
pub struct RuntimeGuard {
    inner: RuntimeGuardInner,
}

impl std::fmt::Debug for RuntimeGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeGuard")
            .field(
                "shutdown_completed",
                &self.inner.shutdown_completed.load(Ordering::Acquire),
            )
            .finish()
    }
}

impl RuntimeGuard {
    pub(crate) fn new(inner: RuntimeGuardInner) -> Self {
        Self { inner }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.inner.cancelled.load(Ordering::Acquire)
            && !self.inner.shutdown_completed.load(Ordering::Acquire)
    }

    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
        #[cfg(feature = "tokio")]
        if let Some(abort) = &self.inner.abort_handle {
            abort.abort();
        }
    }
}

impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        self.inner.cancelled.store(true, Ordering::Release);
        #[cfg(feature = "tokio")]
        if let Some(abort) = &self.inner.abort_handle {
            abort.abort();
        }
        if !self.inner.shutdown_completed.load(Ordering::Acquire) {
            self.inner
                .observer
                .observe(WriteEvent::GuardDroppedBeforeShutdown);
        }
    }
}
