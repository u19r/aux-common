use std::sync::Arc;

use crate::{LoadUnavailable, SharedCause, SharedLoadError};

struct OpaqueCause;

#[derive(Clone)]
enum DomainError {
    Source(SharedCause<OpaqueCause>),
    Unavailable(LoadUnavailable),
}

impl From<LoadUnavailable> for DomainError {
    fn from(reason: LoadUnavailable) -> Self {
        Self::Unavailable(reason)
    }
}

#[test]
fn given_non_cloneable_cause_when_domain_error_is_shared_then_owned_errors_retain_source_identity()
{
    let error = Arc::new(DomainError::Source(SharedCause::from(OpaqueCause)));
    let first = SharedLoadError::Source(Arc::clone(&error)).into_owned();
    let second = SharedLoadError::Source(error).into_owned();
    let (DomainError::Source(first), DomainError::Source(second)) = (first, second) else {
        panic!("source category changed");
    };
    assert!(std::ptr::eq(first.as_ref(), second.as_ref()));
}

#[test]
fn given_unavailable_load_when_converted_then_domain_policy_receives_the_typed_reason() {
    for reason in [LoadUnavailable::Full, LoadUnavailable::Cancelled] {
        let error = match reason {
            LoadUnavailable::Full => SharedLoadError::<DomainError>::Full,
            LoadUnavailable::Cancelled => SharedLoadError::Cancelled,
        };
        assert!(matches!(error.into_owned(), DomainError::Unavailable(actual) if actual == reason));
    }
}

#[test]
fn given_opaque_cause_when_diagnostics_are_formatted_then_only_the_fixed_category_is_exposed() {
    let cause = SharedCause::from(OpaqueCause);
    assert_eq!(cause.to_string(), "shared source error");
    assert_eq!(format!("{cause:?}"), "shared source error");
}
