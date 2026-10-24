mod validation;

pub(crate) use validation::ClaimsPolicy;
#[cfg(test)]
pub(crate) use validation::{AudienceRef, RegisteredClaimRefs};

#[cfg(test)]
mod validation_tests;
