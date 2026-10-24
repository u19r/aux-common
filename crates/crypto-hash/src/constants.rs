pub const API_KEY_HASH_ALGO: &str = "sha3-512";
pub(crate) const API_KEY_SALT_BYTES: usize = 16;
pub(crate) const API_KEY_SALT_B64_BYTES: usize = 22;
pub(crate) const API_KEY_DIGEST_BYTES: usize = 64;
pub(crate) const API_KEY_DIGEST_B64_BYTES: usize = 86;

pub const ARGON2_MEMORY_KIB: u32 = 19_456;
pub const ARGON2_PARALLELISM: u32 = 1;
pub const ARGON2_VERSION: u32 = 19;
pub const ARGON2_SALT_BYTES: usize = 16;
pub const ARGON2_HASH_OUTPUT_BYTES: usize = 32;
pub(crate) const ARGON2_ITERATIONS: u32 = 3;
pub(crate) const MAX_PASSWORD_HASH_BYTES: usize = 1024;
