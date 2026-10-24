use std::{
    collections::HashMap,
    fmt,
    future::Future,
    hash::Hash,
    sync::{Arc, Mutex},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

use crate::{LoadUnavailable, RefreshDemand, RefreshPriority};

type LoadResult<V, E> = Arc<Result<V, Arc<E>>>;
type LoadChannel<V, E> = watch::Sender<Option<LoadResult<V, E>>>;
type LoadMap<K, V, E> = Arc<Mutex<HashMap<K, (LoadChannel<V, E>, RefreshPriority)>>>;

/// Bounded per-key fetch ownership. Results live only through completion;
/// callers own value residence, negative caching, and source freshness.
///
/// Cancellation of the leader cancels its current subscribers. A later caller
/// may retry. Cancellation of a subscriber does not cancel the leader.
pub struct SharedLoad<K, V, E> {
    flights: LoadMap<K, V, E>,
    waiters: Arc<Semaphore>,
    max_keys: usize,
    max_waiters: usize,
}

pub enum SharedLoadError<E> {
    Source(Arc<E>),
    Full,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedLoadStats {
    pub active_keys: usize,
    pub subscribers: usize,
}

struct LoadLeader<K: Eq + Hash, V, E> {
    key: K,
    channel: LoadChannel<V, E>,
    flights: LoadMap<K, V, E>,
}

enum LoadRole<K: Eq + Hash, V, E> {
    Leader(LoadLeader<K, V, E>),
    Subscriber {
        channel: watch::Receiver<Option<LoadResult<V, E>>>,
        permit: OwnedSemaphorePermit,
    },
}

impl<K, V, E> SharedLoad<K, V, E>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    /// Active keys reserve independent leader capacity; a hot key cannot spend
    /// those slots through follower fan-in. Total admission is bounded by
    /// `max_keys + max_waiters`. Zero limits normalize to one, and waiter
    /// limits are capped by the runtime semaphore's representable permit
    /// count.
    #[must_use]
    pub fn new(max_keys: usize, max_waiters: usize) -> Self {
        let max_waiters = max_waiters.clamp(1, Semaphore::MAX_PERMITS);
        Self {
            flights: Arc::new(Mutex::new(HashMap::new())),
            waiters: Arc::new(Semaphore::new(max_waiters)),
            max_keys: max_keys.max(1),
            max_waiters,
        }
    }

    /// All admitted subscribers observe the same value, absence (when `V` is
    /// optional), or typed source error. Full admission never starts a fetch.
    /// Prefer cheap shared values such as `Arc<T>` for `V`.
    pub async fn fetch<F, Fut>(&self, key: &K, fetch: F) -> Result<V, SharedLoadError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        let outcome = match self.admit_fetch(key)? {
            LoadRole::Leader(leader) => {
                let outcome = Arc::new(fetch().await.map_err(Arc::new));
                leader.channel.send_replace(Some(Arc::clone(&outcome)));
                outcome
            }
            LoadRole::Subscriber {
                mut channel,
                permit: _permit,
            } => loop {
                if let Some(outcome) = channel.borrow_and_update().as_ref().map(Arc::clone) {
                    break outcome;
                }
                channel
                    .changed()
                    .await
                    .map_err(|_| SharedLoadError::Cancelled)?;
            },
        };
        match outcome.as_ref() {
            Ok(value) => Ok(value.clone()),
            Err(error) => Err(SharedLoadError::Source(Arc::clone(error))),
        }
    }

    #[must_use]
    pub fn stats(&self) -> SharedLoadStats {
        let flights = self
            .flights
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        SharedLoadStats {
            active_keys: flights.len(),
            subscribers: flights.len() + self.max_waiters - self.waiters.available_permits(),
        }
    }

    fn admit_fetch(&self, key: &K) -> Result<LoadRole<K, V, E>, SharedLoadError<E>> {
        let mut flights = self
            .flights
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some((channel, priority)) = flights.get(key) {
            let permit = Arc::clone(&self.waiters)
                .try_acquire_owned()
                .map_err(|_| SharedLoadError::Full)?;
            if RefreshDemand::current() == RefreshDemand::Cold {
                priority.promote_cold();
            }
            return Ok(LoadRole::Subscriber {
                channel: channel.subscribe(),
                permit,
            });
        }
        if flights.len() >= self.max_keys {
            return Err(SharedLoadError::Full);
        }
        let (channel, _) = watch::channel(None);
        flights.insert(key.clone(), (channel.clone(), RefreshPriority::current()));
        Ok(LoadRole::Leader(LoadLeader {
            key: key.clone(),
            channel,
            flights: Arc::clone(&self.flights),
        }))
    }
}

impl<K, V, E> Drop for LoadLeader<K, V, E>
where K: Eq + Hash
{
    fn drop(&mut self) {
        let mut flights = self
            .flights
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        flights.remove(&self.key);
    }
}

impl<E: Clone + From<LoadUnavailable>> SharedLoadError<E> {
    /// Preserve the domain's owned error contract while sharing opaque causes.
    pub fn into_owned(self) -> E {
        match self {
            Self::Source(error) => error.as_ref().clone(),
            Self::Full => LoadUnavailable::Full.into(),
            Self::Cancelled => LoadUnavailable::Cancelled.into(),
        }
    }
}

impl<E> fmt::Display for SharedLoadError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Source(_) => "shared fetch failed",
            Self::Full => "shared fetch capacity exhausted",
            Self::Cancelled => "shared fetch cancelled",
        })
    }
}

impl<E> fmt::Debug for SharedLoadError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl<E: std::error::Error + 'static> std::error::Error for SharedLoadError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(error) => Some(error.as_ref()),
            Self::Full | Self::Cancelled => None,
        }
    }
}
