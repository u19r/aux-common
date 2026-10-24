use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use crate::{
    model::{WakeFuture, WakeScheduler, WakeSchedulerError},
    time::MonotonicDeadline,
};

/// Runtime-neutral virtual time and wake source for deterministic consumer
/// tests.
///
/// Clone the profile into the system's
/// [`WakeScheduler`](crate::runtime::WakeScheduler) and advance it explicitly
/// from the test. No thread, runtime timer, or wall clock is used.
#[derive(Clone, Default)]
pub struct TestProfile {
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    now: u64,
    sleepers: Vec<Arc<Sleeper>>,
}

struct Sleeper {
    deadline: u64,
    state: Mutex<SleeperState>,
}

#[derive(Default)]
struct SleeperState {
    ready: bool,
    waker: Option<Waker>,
}

struct TestSleep {
    state: Arc<Mutex<State>>,
    sleeper: Arc<Sleeper>,
}

impl TestProfile {
    /// Creates a profile at virtual monotonic time zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current virtual monotonic time.
    pub fn now(&self) -> MonotonicDeadline {
        let now = self.state.lock().map(|state| state.now).unwrap_or(u64::MAX);
        MonotonicDeadline::from_nanos(now)
    }

    /// Advances virtual time and wakes every sleep whose deadline is reached.
    pub fn advance(&self, duration: Duration) {
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        let current = self.now().as_nanos();
        self.advance_to(MonotonicDeadline::from_nanos(current.saturating_add(nanos)));
    }

    /// Moves virtual time forward to `deadline` and wakes due sleeps.
    pub fn advance_to(&self, deadline: MonotonicDeadline) {
        let mut wakers = Vec::new();
        if let Ok(mut state) = self.state.lock() {
            state.now = state.now.max(deadline.as_nanos());
            for sleeper in &state.sleepers {
                if sleeper.deadline > state.now {
                    continue;
                }
                if let Ok(mut sleeper) = sleeper.state.lock() {
                    if sleeper.ready {
                        continue;
                    }
                    sleeper.ready = true;
                    if let Some(waker) = sleeper.waker.take() {
                        wakers.push(waker);
                    }
                }
            }
        }
        for waker in wakers {
            waker.wake();
        }
    }
}

impl WakeScheduler for TestProfile {
    fn sleep(&self, delay: Duration) -> Result<WakeFuture, WakeSchedulerError> {
        let delay = u64::try_from(delay.as_nanos()).unwrap_or(u64::MAX);
        let mut state = self
            .state
            .lock()
            .map_err(|_| WakeSchedulerError::Unavailable)?;
        let sleeper = Arc::new(Sleeper {
            deadline: state.now.saturating_add(delay),
            state: Mutex::new(SleeperState::default()),
        });
        state.sleepers.push(Arc::clone(&sleeper));
        Ok(Box::pin(TestSleep {
            state: Arc::clone(&self.state),
            sleeper,
        }))
    }
}

impl Future for TestSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let sleep = self.get_mut();
        let Ok(state) = sleep.state.lock() else {
            return Poll::Ready(());
        };
        let now = state.now;
        drop(state);
        let Ok(mut sleeper) = sleep.sleeper.state.lock() else {
            return Poll::Ready(());
        };
        if sleeper.ready || sleep.sleeper.deadline <= now {
            sleeper.ready = true;
            return Poll::Ready(());
        }
        sleeper.waker = Some(context.waker().clone());
        Poll::Pending
    }
}
