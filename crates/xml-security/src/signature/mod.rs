mod verification;

pub use verification::{
    EnvelopedSignature, SignatureVerifier, VerifiedElement, VerifiedXmlDocument,
};

#[cfg(test)]
mod verification_tests;
