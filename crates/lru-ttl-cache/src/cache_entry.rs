use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{config::CacheExpiration, refresh_cancellation::RefreshCancellation};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct EntryIdentity(usize);

#[derive(Clone)]
pub(super) struct CacheEntry<V> {
    inner: Arc<EntryInner<V>>,
}

struct EntryInner<V> {
    value: V,
    inserted_at: Instant,
    expiration: CacheExpiration,
    expires_at: Option<Instant>,
    refreshing: AtomicBool,
    refresh_cancelled: AtomicBool,
    refresh_handle: Mutex<Option<RefreshCancellation>>,
}

impl<V> CacheEntry<V> {
    pub(super) fn new(value: V, expiration: CacheExpiration) -> Self {
        let inserted_at = Instant::now();
        let expires_at = match expiration {
            CacheExpiration::Ttl(ttl) => Some(inserted_at.checked_add(ttl).unwrap_or(inserted_at)),
            CacheExpiration::Never => None,
        };
        Self {
            inner: Arc::new(EntryInner {
                value,
                inserted_at,
                expiration,
                expires_at,
                refreshing: AtomicBool::new(false),
                refresh_cancelled: AtomicBool::new(false),
                refresh_handle: Mutex::new(None),
            }),
        }
    }

    pub(super) fn is_expired_at(&self, now: Instant) -> bool {
        self.inner
            .expires_at
            .is_some_and(|expires_at| now >= expires_at)
    }

    pub(super) fn is_stale_at(&self, now: Instant, stale_ttl: Duration) -> bool {
        if stale_ttl.is_zero() {
            return false;
        }
        self.inner
            .expires_at
            .and_then(|expires_at| expires_at.checked_add(stale_ttl))
            .is_some_and(|stale_until| now < stale_until)
    }

    pub(super) fn expiration(&self) -> CacheExpiration {
        self.inner.expiration
    }

    pub(super) fn expiration_key(&self) -> Option<(Instant, EntryIdentity)> {
        self.inner.expires_at.map(|deadline| {
            // Live entries have distinct allocation identities. The index
            // removes this identity before releasing the stored entry.
            (deadline, EntryIdentity(Arc::as_ptr(&self.inner) as usize))
        })
    }

    pub(super) fn should_refresh(&self, refresh_ttl: Duration) -> bool {
        self.inner.inserted_at.elapsed() >= refresh_ttl
    }

    pub(super) fn begin_refresh(&self) -> bool {
        let started = self
            .inner
            .refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if started {
            self.inner.refresh_cancelled.store(false, Ordering::Release);
        }
        started
    }

    pub(super) fn finish_refresh(&self) {
        self.inner.refreshing.store(false, Ordering::Release);
        lock_unpoisoned(&self.inner.refresh_handle).take();
    }

    pub(super) fn install_refresh_handle(&self, handle: RefreshCancellation) {
        if self.inner.refresh_cancelled.load(Ordering::Acquire) {
            handle.abort();
            return;
        }
        *lock_unpoisoned(&self.inner.refresh_handle) = Some(handle);
    }

    pub(super) fn cancel_refresh(&self) {
        self.inner.refresh_cancelled.store(true, Ordering::Release);
        if let Some(handle) = lock_unpoisoned(&self.inner.refresh_handle).take() {
            handle.abort();
        }
    }

    pub(super) fn is_same_entry(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub(super) fn value(&self) -> &V {
        &self.inner.value
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
