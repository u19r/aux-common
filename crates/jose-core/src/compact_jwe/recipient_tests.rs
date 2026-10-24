use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    encoding::{AsDer, PublicKeyX509Der},
    rsa::{KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, PrivateDecryptingKey},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use super::JweRecipient;

#[test]
fn given_registered_rsa_recipient_when_encrypting_then_only_recipient_opens_authenticated_nested_jwt()
 {
    let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
    let public: PublicKeyX509Der<'_> = private.public_key().as_der().unwrap();
    let recipient = JweRecipient::try_new("recipient-1", public.as_ref()).unwrap();
    let plaintext = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2ln";
    let encrypted = recipient.encrypt_nested_jwt(plaintext).unwrap();
    let second = recipient.encrypt_nested_jwt(plaintext).unwrap();
    assert_ne!(encrypted, second);
    let parts: Vec<_> = encrypted.split('.').collect();
    assert_eq!(parts.len(), 5);
    let protected: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(
        protected,
        serde_json::json!({"alg":"RSA-OAEP-256","enc":"A256GCM","cty":"JWT","kid":"recipient-1"})
    );
    let wrapped = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let iv: [u8; 12] = URL_SAFE_NO_PAD
        .decode(parts[2])
        .unwrap()
        .try_into()
        .unwrap();
    let private = OaepPrivateDecryptingKey::new(private).unwrap();
    let mut key_bytes = vec![0; private.min_output_size()];
    let key = private
        .decrypt(&OAEP_SHA256_MGF1SHA256, &wrapped, &mut key_bytes, None)
        .unwrap();
    assert_eq!(key.len(), 32);
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).unwrap());
    let mut ciphertext = URL_SAFE_NO_PAD.decode(parts[3]).unwrap();
    ciphertext.extend(URL_SAFE_NO_PAD.decode(parts[4]).unwrap());
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 1;
    assert!(
        key.open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::from(parts[0].as_bytes()),
            &mut tampered
        )
        .is_err()
    );
    let mut wrong_header = ciphertext.clone();
    assert!(
        key.open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::from(b"substituted-header"),
            &mut wrong_header
        )
        .is_err()
    );
    let opened = key
        .open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::from(parts[0].as_bytes()),
            &mut ciphertext,
        )
        .unwrap();
    assert_eq!(opened, plaintext.as_bytes());
    let other =
        OaepPrivateDecryptingKey::new(PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap())
            .unwrap();
    assert!(
        other
            .decrypt(&OAEP_SHA256_MGF1SHA256, &wrapped, &mut key_bytes, None)
            .is_err()
    );
    for invalid in ["", "a.b", "a..c", "a.b.c.d"] {
        assert!(recipient.encrypt_nested_jwt(invalid).is_err());
    }
    assert!(JweRecipient::try_new("", public.as_ref()).is_err());
    assert!(JweRecipient::try_new("key", b"invalid DER").is_err());
}
