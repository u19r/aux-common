use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use password_hash::phc::PasswordHash;

use crate::HashError;

pub const ARGON2_MEMORY_KIB: u32 = 19_456;
pub const ARGON2_PARALLELISM: u32 = 1;
pub const ARGON2_VERSION: u32 = 19;
pub const ARGON2_SALT_BYTES: usize = 16;
pub const ARGON2_HASH_OUTPUT_BYTES: usize = 32;
const ARGON2_ITERATIONS: u32 = 3;
const MAX_PASSWORD_HASH_BYTES: usize = 1024;

/// Explicit Argon2id acceptance policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Policy {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    version: u32,
    salt_bytes: usize,
    output_bytes: usize,
}

impl Argon2Policy {
    /// The public default used for newly generated and verified passwords.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            parallelism: ARGON2_PARALLELISM,
            version: ARGON2_VERSION,
            salt_bytes: ARGON2_SALT_BYTES,
            output_bytes: ARGON2_HASH_OUTPUT_BYTES,
        }
    }

    /// A bounded compatibility policy for records produced by an older policy.
    #[must_use]
    pub const fn bounded_legacy() -> Self {
        Self {
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            parallelism: 0,
            version: ARGON2_VERSION,
            salt_bytes: ARGON2_SALT_BYTES,
            output_bytes: ARGON2_HASH_OUTPUT_BYTES,
        }
    }

    #[must_use]
    pub const fn parallelism(self) -> u32 {
        self.parallelism
    }

    fn accepts(self, parsed: &PasswordHash) -> bool {
        parsed.algorithm.as_str() == "argon2id"
            && parsed.version == Some(self.version)
            && parsed.params.get_decimal("m") == Some(self.memory_kib)
            && parsed.params.get_decimal("t") == Some(self.iterations)
            && parsed.params.get_decimal("p").is_some_and(|parallelism| {
                if self.parallelism == 0 {
                    (1..=64).contains(&parallelism)
                } else {
                    parallelism == self.parallelism
                }
            })
            && parsed
                .salt
                .is_some_and(|salt| salt.as_ref().len() == self.salt_bytes)
            && parsed
                .hash
                .is_some_and(|hash| hash.len() == self.output_bytes)
    }

    fn argon2(self) -> Result<Argon2<'static>, HashError> {
        let params = Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(self.output_bytes),
        )
        .map_err(|_| HashError::PasswordHashing)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Hash a password with the strict public Argon2id policy.
pub fn hash_password(password: &[u8]) -> Result<String, HashError> {
    let policy = Argon2Policy::strict();
    policy
        .argon2()?
        .hash_password(password)
        .map(|hash| hash.to_string())
        .map_err(|_| HashError::PasswordHashing)
}

/// Verify a password against the strict public Argon2id policy.
pub fn verify_password(password: &[u8], encoded_hash: &str) -> Result<bool, HashError> {
    verify_password_with_policy(password, encoded_hash, Argon2Policy::strict())
}

/// Verify a password against an explicitly selected policy.
pub fn verify_password_with_policy(
    password: &[u8],
    encoded_hash: &str,
    policy: Argon2Policy,
) -> Result<bool, HashError> {
    if encoded_hash.len() > MAX_PASSWORD_HASH_BYTES {
        return Err(HashError::InvalidPasswordHash);
    }
    let parsed = PasswordHash::new(encoded_hash).map_err(|_| HashError::InvalidPasswordHash)?;
    if !policy.accepts(&parsed) {
        return Err(HashError::PasswordPolicy);
    }
    let parallelism = parsed
        .params
        .get_decimal("p")
        .ok_or(HashError::PasswordPolicy)?;
    let params = Params::new(
        policy.memory_kib,
        policy.iterations,
        parallelism,
        Some(policy.output_bytes),
    )
    .map_err(|_| HashError::PasswordPolicy)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    Ok(argon2.verify_password(password, &parsed).is_ok())
}
