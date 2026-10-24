use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
    rsa::{OAEP_SHA256_MGF1SHA256, OaepPublicEncryptingKey},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use crate::{
    JoseError,
    constants::{JWE_CONTENT_KEY_BYTES, JWE_IV_BYTES},
};

pub(super) fn encrypt_nested_jwt(
    recipient: &OaepPublicEncryptingKey,
    protected_header: &str,
    plaintext: &[u8],
) -> Result<String, JoseError> {
    let rng = SystemRandom::new();
    let mut content_key = Zeroizing::new([0_u8; JWE_CONTENT_KEY_BYTES]);
    rng.fill(&mut *content_key)
        .map_err(|_| JoseError::EncryptionFailed)?;
    let mut wrapped_key = vec![0_u8; recipient.ciphertext_size()];
    let wrapped_key = recipient
        .encrypt(
            &OAEP_SHA256_MGF1SHA256,
            &*content_key,
            &mut wrapped_key,
            None,
        )
        .map_err(|_| JoseError::EncryptionFailed)?;
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &*content_key).map_err(|_| JoseError::EncryptionFailed)?,
    );
    let mut iv = [0_u8; JWE_IV_BYTES];
    rng.fill(&mut iv).map_err(|_| JoseError::EncryptionFailed)?;
    let mut ciphertext = plaintext.to_vec();
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(iv),
            Aad::from(protected_header.as_bytes()),
            &mut ciphertext,
        )
        .map_err(|_| JoseError::EncryptionFailed)?;
    Ok(format!(
        "{}.{}.{}.{}.{}",
        protected_header,
        URL_SAFE_NO_PAD.encode(wrapped_key),
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(ciphertext),
        URL_SAFE_NO_PAD.encode(tag.as_ref())
    ))
}
