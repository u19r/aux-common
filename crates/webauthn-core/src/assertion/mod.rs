mod verification;

#[cfg(test)]
mod test_support;

#[cfg(test)]
pub(crate) use test_support::{
    CHALLENGE_B64, assertion_fixture, assertion_policy, attestation_fixture, attestation_policy,
    cose_key, nested_array_value, policy,
};
#[cfg(test)]
pub(crate) use verification::classify_counter;
pub(crate) use verification::parse_authenticator_data;
pub use verification::verify_assertion;

#[cfg(test)]
mod verification_tests;
