mod constants;
mod verification;

pub use verification::{
    DigestAlgorithm, SignatureAlgorithm, UnverifiedPublicKeyDer, compute_digest, verify_saml_xml,
    verify_signature,
};

#[cfg(test)]
mod verification_tests;
