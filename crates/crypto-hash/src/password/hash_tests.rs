use super::{Argon2Policy, hash_password, verify_password, verify_password_with_policy};

#[test]
fn given_password_when_hashing_then_strict_policy_roundtrips() {
    let hash = hash_password(b"secret").expect("hash");
    assert!(verify_password(b"secret", &hash).expect("verify"));
    assert!(!verify_password(b"wrong", &hash).expect("verify"));
    assert_eq!(Argon2Policy::strict().parallelism(), 1);
}

#[test]
fn given_legacy_parallelism_when_verifying_strictly_then_policy_rejects_it() {
    let legacy = "$argon2id$v=19$m=19456,t=3,p=8$Lud2zb0Z6RvFEWl1YiQ12A$pK/4X7HO3sxc5hykR/\
                  yvTqghqQOfzU10DLem+o9tlA8";
    assert_eq!(
        verify_password(b"auxfn-dummy-password-verification-only", legacy),
        Err(crate::HashError::PasswordPolicy)
    );
    assert!(
        verify_password_with_policy(
            b"auxfn-dummy-password-verification-only",
            legacy,
            Argon2Policy::bounded_legacy()
        )
        .expect("legacy verify")
    );
}

#[test]
fn given_oversized_password_hash_when_verifying_then_reject_before_argon2() {
    let oversized = "$argon2id$v=19$m=19456,t=3,p=1$".to_owned() + &"A".repeat(2 * 1024);
    assert_eq!(
        verify_password(b"secret", &oversized),
        Err(crate::HashError::InvalidPasswordHash)
    );
}
