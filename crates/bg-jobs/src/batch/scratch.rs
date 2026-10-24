//! Reusable bounded storage for batch payloads and decoded results.

/// Reusable bounded scratch storage for batch payloads and decoded results.
///
/// Clearing drops each value while retaining at most the configured capacity;
/// adapters can explicitly shrink after a traffic-shape change.
#[derive(Clone, Debug)]
pub struct ScratchStorage<T> {
    values: Vec<T>,
    retained_capacity: usize,
}

impl<T> ScratchStorage<T> {
    pub fn new(retained_capacity: usize) -> Self {
        Self {
            values: Vec::with_capacity(retained_capacity),
            retained_capacity,
        }
    }

    pub fn push(&mut self, value: T) {
        self.values.push(value);
    }

    pub fn clear(&mut self) {
        self.values.clear();
    }

    pub fn shrink_to_retained_cap(&mut self) {
        self.values.shrink_to(self.retained_capacity);
    }

    pub fn capacity(&self) -> usize {
        self.values.capacity()
    }

    #[cfg(feature = "test-support")]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    #[cfg(feature = "test-support")]
    pub fn as_slice(&self) -> &[T] {
        &self.values
    }
}
