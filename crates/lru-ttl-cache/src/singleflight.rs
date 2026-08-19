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
#[path = "singleflight_tests.rs"]
mod singleflight_tests;
