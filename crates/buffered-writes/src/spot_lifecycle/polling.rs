use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use futures_util::{
    FutureExt,
    future::{AbortHandle, Abortable, Aborted, BoxFuture, Shared},
};
use tokio::time::Instant;

use super::{action::SpotInstanceAction, spot_action_source::SpotActionSource};
use crate::{
    LifecycleError, WriteEvent, WriteObserver,
    constants::{DEFAULT_SPOT_POLL_INTERVAL, MIN_SPOT_POLL_INTERVAL},
};

type PollResult = Result<Option<SpotInstanceAction>, LifecycleError>;
type SpotPoll = Shared<BoxFuture<'static, Result<PollResult, Aborted>>>;

struct ActivePoll {
    future: SpotPoll,
    abort: AbortHandle,
}

impl ActivePoll {
    fn cancel(self) {
        self.abort.abort();
    }
}

struct PollState {
    next_poll_at: Instant,
    in_flight: Option<ActivePoll>,
    interval: Duration,
    is_closed: bool,
    waiters: usize,
}

pub(super) struct SpotPolling {
    state: Mutex<PollState>,
}

impl Default for SpotPolling {
    fn default() -> Self {
        Self {
            state: Mutex::new(PollState {
                next_poll_at: Instant::now(),
                in_flight: None,
                interval: DEFAULT_SPOT_POLL_INTERVAL,
                is_closed: false,
                waiters: 0,
            }),
        }
    }
}

pub(super) enum PollTurn {
    HostOnly,
    Wait(Duration),
    Active(SpotPoll),
}

impl SpotPolling {
    pub(super) fn set_interval(&self, interval: Duration) -> Result<(), LifecycleError> {
        if interval < MIN_SPOT_POLL_INTERVAL || Instant::now().checked_add(interval).is_none() {
            return Err(LifecycleError::InvalidConfiguration {
                reason: "Spot poll interval must be at least 5ms and fit a monotonic deadline",
            });
        }
        self.lock_state()?.interval = interval;
        Ok(())
    }

    pub(super) fn next_turn(
        &self,
        source: &dyn SpotActionSource,
    ) -> Result<PollTurn, LifecycleError> {
        let mut state = self.lock_state()?;
        if state.is_closed {
            return Ok(PollTurn::HostOnly);
        }
        if let Some(poll) = &state.in_flight {
            return Ok(PollTurn::Active(poll.future.clone()));
        }
        let now = Instant::now();
        if state.next_poll_at > now {
            return Ok(PollTurn::Wait(state.next_poll_at - now));
        }
        state.next_poll_at =
            now.checked_add(state.interval)
                .ok_or(LifecycleError::InvalidConfiguration {
                    reason: "Spot poll interval no longer fits a monotonic deadline",
                })?;
        let (abort, registration) = AbortHandle::new_pair();
        let poll = Abortable::new(source.poll_spot_action(), registration)
            .boxed()
            .shared();
        state.in_flight = Some(ActivePoll {
            future: poll.clone(),
            abort,
        });
        Ok(PollTurn::Active(poll))
    }

    pub(super) fn complete_poll(&self, poll: &SpotPoll) -> Result<(), LifecycleError> {
        let mut state = self.lock_state()?;
        if state
            .in_flight
            .as_ref()
            .is_some_and(|active| active.future.ptr_eq(poll))
        {
            state.in_flight = None;
        }
        Ok(())
    }

    pub(super) fn cancel_poll(&self) -> Result<(), LifecycleError> {
        if let Some(poll) = self.lock_state()?.in_flight.take() {
            poll.cancel();
        }
        Ok(())
    }

    pub(super) fn close(&self) -> Result<(), LifecycleError> {
        let mut state = self.lock_state()?;
        state.is_closed = true;
        if let Some(poll) = state.in_flight.take() {
            poll.cancel();
        }
        Ok(())
    }

    fn begin_waiter(&self) -> Result<(), LifecycleError> {
        let mut state = self.lock_state()?;
        state.waiters = state
            .waiters
            .checked_add(1)
            .ok_or(LifecycleError::SourceUnavailable {
                reason: "too many concurrent Spot event waiters",
            })?;
        Ok(())
    }

    fn finish_waiter(&self, exit: WaiterExit) -> Result<(), LifecycleError> {
        let mut state = self.lock_state()?;
        state.waiters = state
            .waiters
            .checked_sub(1)
            .ok_or(LifecycleError::SourceUnavailable {
                reason: "Spot event waiter ownership is invalid",
            })?;
        match exit {
            WaiterExit::Completed => {}
            WaiterExit::Cancelled if state.waiters == 0 => {
                if let Some(poll) = state.in_flight.take() {
                    poll.cancel();
                }
            }
            WaiterExit::Cancelled => {}
        }
        Ok(())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, PollState>, LifecycleError> {
        self.state
            .lock()
            .map_err(|_| LifecycleError::SourceUnavailable {
                reason: "Spot discovery state is unavailable",
            })
    }
}

impl PollTurn {
    pub(super) async fn await_output(self) -> Option<(SpotPoll, Result<PollResult, Aborted>)> {
        match self {
            Self::HostOnly => std::future::pending().await,
            Self::Wait(delay) => {
                tokio::time::sleep(delay).await;
                None
            }
            Self::Active(poll) => {
                let output = poll.clone().await;
                Some((poll, output))
            }
        }
    }
}

// Normal response events preserve the shared poll. The last cancelled waiter
// releases it even when a notification handle keeps the adapter alive.
#[derive(Clone, Copy)]
enum WaiterExit {
    Completed,
    Cancelled,
}

pub(super) struct PollWaitGuard {
    polling: Arc<SpotPolling>,
    observer: Arc<dyn WriteObserver>,
    exit: WaiterExit,
}

impl PollWaitGuard {
    pub(super) fn try_new(
        polling: Arc<SpotPolling>,
        observer: Arc<dyn WriteObserver>,
    ) -> Result<Self, LifecycleError> {
        polling.begin_waiter()?;
        Ok(Self {
            polling,
            observer,
            exit: WaiterExit::Cancelled,
        })
    }

    pub(super) fn finish(mut self) {
        self.exit = WaiterExit::Completed;
    }
}

impl Drop for PollWaitGuard {
    fn drop(&mut self) {
        if let Err(error) = self.polling.finish_waiter(self.exit) {
            self.observer
                .observe(WriteEvent::LifecycleSourceFailed { error });
        }
    }
}
