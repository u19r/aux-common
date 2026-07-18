use std::{
    collections::HashMap,
    hash::Hash,
    sync::{Arc, Mutex, Weak},
};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// Coordinates one active operation per key without imposing a global worker or
/// slot limit.
#[derive(Clone)]
pub struct KeyedSingleflight<K> {
    gates: Arc<Mutex<HashMap<K, Weak<AsyncMutex<()>>>>>,
}

impl<K> Default for KeyedSingleflight<K> {
    fn default() -> Self {
        Self {
            gates: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<K> KeyedSingleflight<K>
where K: Clone + Eq + Hash
{
    pub async fn lock(&self, key: &K) -> KeyedSingleflightGuard<K> {
        let gate = {
            let mut gates = lock_unpoisoned(&self.gates);
            if let Some(gate) = gates.get(key).and_then(Weak::upgrade) {
                gate
            } else {
                let gate = Arc::new(AsyncMutex::new(()));
                gates.insert(key.clone(), Arc::downgrade(&gate));
                gate
            }
        };
        let guard = Arc::clone(&gate).lock_owned().await;
        KeyedSingleflightGuard {
            key: key.clone(),
            gate,
            guard: Some(guard),
            gates: Arc::clone(&self.gates),
        }
    }

    #[cfg(test)]
    fn active_key_count(&self) -> usize {
        lock_unpoisoned(&self.gates).len()
    }
}

pub struct KeyedSingleflightGuard<K>
where K: Eq + Hash
{
    key: K,
    gate: Arc<AsyncMutex<()>>,
    guard: Option<OwnedMutexGuard<()>>,
    gates: Arc<Mutex<HashMap<K, Weak<AsyncMutex<()>>>>>,
}

impl<K> Drop for KeyedSingleflightGuard<K>
where K: Eq + Hash
{
    fn drop(&mut self) {
        self.guard.take();
        if Arc::strong_count(&self.gate) != 1 {
            return;
        }
        let mut gates = lock_unpoisoned(&self.gates);
        if gates
            .get(&self.key)
            .and_then(Weak::upgrade)
            .is_some_and(|current| Arc::ptr_eq(&current, &self.gate))
        {
            gates.remove(&self.key);
        }
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::KeyedSingleflight;

    #[tokio::test]
    async fn same_key_serializes_while_different_keys_remain_concurrent_and_cleanup() {
        let singleflight = KeyedSingleflight::default();
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for key in ["same", "same", "other"] {
            let singleflight = singleflight.clone();
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            tasks.spawn(async move {
                let _guard = singleflight.lock(&key).await;
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(current, Ordering::SeqCst);
                tokio::task::yield_now().await;
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.expect("singleflight task");
        }

        assert_eq!(maximum.load(Ordering::SeqCst), 2);
        assert_eq!(singleflight.active_key_count(), 0);
    }
}
