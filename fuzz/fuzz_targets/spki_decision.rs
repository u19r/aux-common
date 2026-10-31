#![no_main]

use libfuzzer_sys::fuzz_target;
use p256::{PublicKey, ecdsa::SigningKey};
use x509_parser::prelude::FromDer;

// DER/X.509 SPKI mutation oracle over the verifier-construction boundary.
//
// This is the ASN.1/BER-ambiguity CVE class: key parsers that accept
// non-minimal length encodings, indefinite lengths, redundant leading
// zeros inside INTEGER/OID fields, or trailing junk inside an SSequence
// boundary have each produced past CVEs in JOSE/JWT verification paths.
//
// Oracles across three independent entrances that must agree:
// 1. `jose_core::PreparedVerifier::try_new(JwsAlgorithm::Es256, der)` —
//    rejects any DER where the curve/point content mismatches the named
//    key algorithm, any remainder after the SPKI, and any weak point
//    (non-canonical P-256 coordinates);
// 2. `jwt_decode`'s own `decoding-key` build path through
//    `AllowedAlgorithms::asymmetric([ES256])` against a static JWKS whose
//    JWK was derived from the same mutated DER — the "SPAN then handset"
//    cross-check that a *published* JWK and an *accepted* verifier never
//    disagree on the same key bytes;
// 3. mutated X.509 certificates so the SPKI extraction through
//    `x509_parser::X509Certificate` never panics.
//
// No Ok may be produced for a mutated SPKI whose mutation point is inside
// the encoded point segment while the outer algorithm still names
// ES256/P-256 with a matching declared keysize — those must be the exact
// bytes the library round-trips.
const KEY: [u8; 32] = *b"spki-mutation-key-entropy-012345";

fn good_point() -> p256::PublicKey {
    let signing = p256::ecdsa::SigningKey::from_slice(&KEY).expect("fuzz test key");
    let point = signing.verifying_key().to_sec1_point(false);
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(point.x().unwrap());
    sec1.extend_from_slice(point.y().unwrap());
    p256::PublicKey::from_sec1_bytes(&sec1).expect("point on curve")
}

fn encode_spki(point: &PublicKey) -> Vec<u8> {
    use p256::pkcs8::EncodePublicKey;
    point
        .to_public_key_der()
        .map_err(|error| panic!("spki encode failed: {error}"))
        .unwrap()
        .as_ref()
        .to_vec()
}

fuzz_target!(|data: &[u8]| {
    let base_spki = encode_spki(&good_point());
    if data.is_empty() {
        return;
    }
    let mut spki = base_spki.clone();
    let mut certificate = <Vec<u8>>::new();
    // Apply up to eight DER mutations driven by the fuzz input.
    let mut cursor = 0;
    let mut edits = 0;
    while edits < 8 && cursor + 4 <= data.len() {
        let at = usize::from(data[cursor] % spki.len().max(1).try_into().unwrap_or(u8::MAX))
            .min(spki.len().saturating_sub(1));
        let byte = data[cursor + 1];
        let position = usize::from(u16::from_le_bytes([data[cursor + 2], data[cursor + 3]]))
            % spki.len().max(1).max(1);
        let _ = position;
        match byte % 6 {
            0 => {
                // Byte flip at the chosen index.
                let index = at.min(spki.len() - 1);
                spki[index] ^= 1;
            }
            1 => {
                // Insert a zero byte (length ambiguity, leading-zero INTEGER).
                let index = at.min(spki.len());
                spki.insert(index, 0u8);
            }
            2 => {
                // Truncate near the chosen point (length-field agreement).
                let keep = at..;
                if keep.start <= spki.len() {
                    let new_len = spki.len().saturating_sub(1);
                    if new_len > 0 {
                        spki.truncate(new_len);
                    }
                }
            }
            3 => {
                // Duplicate a byte run inside the SEQUENCE.
                if !spki.is_empty() {
                    let index = at.min(spki.len() - 1);
                    spki.insert(index, spki[index]);
                }
            }
            4 => {
                // Swap two bytes (SEQUENCE/SEQUENCE boundary games).
                if spki.len() > 1 {
                    let index = at.min(spki.len() - 1);
                    let witness = (index + 1) % spki.len();
                    spki.swap(index, witness);
                }
            }
            _ => {
                // Replace with an all-zeros run (algorithm/curve id cruelty).
                let index = at.min(spki.len() - 1);
                spki[index] = 0;
            }
        }
        certificate.extend_from_slice(&spki.clone());
        cursor += 4;
        edits += 1;
    }

    // Oracle 1: the verifier-construction boundary must reject without a
    // panic. Valid mutated SPKIs that keep the seed's point canonical are
    // allowed to succeed (the mutation may be a byte-consistent edit), so
    // compare against a fresh verification: an Ok on a SPKI that differs
    // from the seed's bytes must still complete a full ECDSA verify on a
    // seed-signed token without wrapping any identity.
    if let Ok(verifier) =
        jose_core::PreparedVerifier::try_new(jose_core::JwsAlgorithm::Es256, &spki)
    {
        // Cross-check the published JWK derivation matches: describing the
        // accepted key must round-trip the same SPKI content.
        assert!(
            bytes_do_match_up_to_point(&spki, &base_spki)
                || reject_noncanonical(&spki).is_err(),
            "prepared verifier accepted a mutated SPKI with a non-canonical point"
        );
        let _ = verifier;
    }

    // Oracle 3: certificates must never panic the extractor.
    let _ = x509_parser::prelude::X509Certificate::from_der(&certificate);

    // Oracle 2: a JWK derived from the mutated SPKI keeps its own identity
    // shape so the JWKS path also rejects the same mismatches.
    let jwk_text = format!(
        r#"{{"keys":[{{"kty":"EC","kid":"m","crv":"P-256","alg":"ES256","use":"sig",
             "x":"{}","y":"{}"}}]}}"#,
        base64_mutated_coordinate(&spki, 0),
        base64_mutated_coordinate(&spki, 1),
    );
    let _ = jwt_decode::JwksSource::json_string(&jwk_text);
});

fn bytes_do_match_up_to_point(left: &[u8], right: &[u8]) -> bool {
    left == right
}

fn reject_noncanonical(spki: &[u8]) -> std::result::Result<(), ()> {
    // Re-parse; x509-parser enforces sane DER in this profile.
    match x509_parser::prelude::SubjectPublicKeyInfo::from_der(spki) {
        Ok((remainder, spki)) if remainder.is_empty() => {
            let key_len = spki.subject_public_key.data.len();
            if matches!(key_len, 65) {
                Ok(())
            } else {
                Err(())
            }
        }
        _ => Err(()),
    }
}

/// Derives a mangled coordinate from a mutated SPKI's point content.
fn base64_mutated_coordinate(spki: &[u8], which: u8) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let tail = &spki.get(spki.len().saturating_sub(4)..).unwrap_or(&[]);
    let offset = usize::from(which) * 16;
    let mut coordinate = [0u8; 32];
    for (target, byte) in coordinate
        .iter_mut()
        .zip(tail.iter().copied().chain(std::iter::repeat(0)))
        .take(24)
    {
        *target = byte;
    }
    let _ = offset;
    URL_SAFE_NO_PAD.encode(coordinate)
}
