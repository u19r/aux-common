use std::{fmt, ops::Deref, sync::Arc};

/// Cloneable ownership of a potentially non-cloneable cause. This container
/// deliberately does not implement `Error`: source derives must dereference it
/// to the concrete cause so typed downcasts retain their existing contract.
pub struct SharedCause<E>(Arc<E>);

impl<E> From<E> for SharedCause<E> {
    fn from(error: E) -> Self {
        Self(Arc::new(error))
    }
}

impl<E> Clone for SharedCause<E> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<E> Deref for SharedCause<E> {
    type Target = E;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<E> AsRef<E> for SharedCause<E> {
    fn as_ref(&self) -> &E {
        self
    }
}

impl<E> fmt::Display for SharedCause<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("shared source error")
    }
}

impl<E> fmt::Debug for SharedCause<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// Coordination failures are distinct from a typed provider failure. Domain
/// errors map these to their unavailable/cold policy through `From`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadUnavailable {
    Full,
    Cancelled,
}

impl LoadUnavailable {
    const fn describe_unavailability(self) -> &'static str {
        match self {
            Self::Full => "cache load capacity exhausted",
            Self::Cancelled => "cache load cancelled",
        }
    }
}

impl fmt::Display for LoadUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.describe_unavailability())
    }
}

impl std::error::Error for LoadUnavailable {}

// Unit and static-message errors are active generic-cache example/test callers.
impl From<LoadUnavailable> for () {
    fn from(_: LoadUnavailable) -> Self {}
}

impl From<LoadUnavailable> for &'static str {
    fn from(error: LoadUnavailable) -> Self {
        error.describe_unavailability()
    }
}
