#![no_main]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use libfuzzer_sys::fuzz_target;
use xml_security::{EnvelopedSignature, SignatureVerifier, VerifiedXmlDocument, XmlSecurityError};

// Structured mutation oracle for enveloped XML signature verification.
//
// The seed is a valid nested-signed document whose digest is computed with
// real SHA-256; only the RSA step is stubbed, because signature mathematics
// belongs to `aws-lc-rs` while signed-element selection, digest binding, and
// fail-closed policy belong here. Every byte-driven edit models an XML
// Signature Wrapping move (sibling injection, subtree duplication, signature
// smuggling, truncation). The oracle: verification may only succeed on the
// byte-identical seed, and the returned canonical bytes must equal the
// precomputed expectation. Any other `Ok` is a wrapping bypass.
struct AcceptingVerifier;

impl SignatureVerifier for AcceptingVerifier {
    fn verify_rsa_sha256(
        &self,
        _canonicalized_signed_info: &[u8],
        _signature: &[u8],
        _public_key_der: &[u8],
    ) -> Result<bool, XmlSecurityError> {
        Ok(true)
    }

    fn sha256_digest(&self, canonicalized_element: &[u8]) -> Result<Vec<u8>, XmlSecurityError> {
        use sha2::{Digest as _, Sha256};
        Ok(Sha256::digest(canonicalized_element).to_vec())
    }
}

const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const TEST_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const TEST_ENV: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const TEST_RSA: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const TEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

const UNSIGNED: &str = r#"<Response xmlns="urn:example" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="resp"><Assertion ID="a1"><Name>alice</Name></Assertion></Response>"#;

fn seed_document() -> String {
    use sha2::{Digest as _, Sha256};
    let parsed = xml_security::UnverifiedElement::parse_unverified(UNSIGNED).expect("seed parses");
    let assertion = parsed
        .child_elements()
        .find(|child| child.attr("ID") == Some("a1"))
        .expect("seed target");
    let canonical = assertion
        .canonicalize_unverified()
        .expect("seed canonicalizes");
    let digest = STANDARD.encode(Sha256::digest(&canonical));
    let signed_info = format!(
        "<ds:SignedInfo xmlns:ds=\"{DS_NS}\"><ds:CanonicalizationMethod \
         Algorithm=\"{TEST_C14N}\"/><ds:SignatureMethod Algorithm=\"{TEST_RSA}\"/><ds:Reference \
         URI=\"#a1\"><ds:Transforms><ds:Transform Algorithm=\"{TEST_ENV}\"/><ds:Transform \
         Algorithm=\"{TEST_C14N}\"/></ds:Transforms><ds:DigestMethod \
         Algorithm=\"{TEST_SHA256}\"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></\
         ds:SignedInfo>"
    );
    UNSIGNED.replacen(
        "</Assertion>",
        &format!(
            "<ds:Signature>{signed_info}<ds:SignatureValue>AA</ds:SignatureValue></ds:Signature></\
             Assertion>"
        ),
        1,
    )
}

fn verify_canonical(document: &str) -> Option<Vec<u8>> {
    let keys = [b"unused-trust-anchor".to_vec()];
    let verified = VerifiedXmlDocument::verify_enveloped_with(
        EnvelopedSignature::new(document, &keys),
        &AcceptingVerifier,
    )
    .ok()?;
    verified.signed_element().canonicalize_unverified().ok()
}

fn apply_edit(document: &mut Vec<char>, op: u8, position: usize, argument: u8) {
    if document.is_empty() {
        return;
    }
    let position = position % (document.len() + 1);
    match op % 6 {
        0 => {
            // Flip a character to a nearby scalar value.
            if position < document.len() {
                let replacement =
                    char::from_u32(document[position] as u32 ^ u32::from(argument) ^ 1)
                        .unwrap_or('?');
                document[position] = replacement;
            }
        }
        1 => {
            // Inject an unsigned sibling with a distinct ID (XSW1 shape).
            let evil: Vec<char> = format!("<Evil ID=\"evil{}\">x</Evil>", argument % 16)
                .chars()
                .collect();
            document.splice(position..position, evil);
        }
        2 => {
            // Delete a span, modeling truncation and tag smuggling.
            let end = (position + usize::from(argument)).min(document.len());
            document.drain(position..end);
        }
        3 => {
            // Reuse the signed ID value on the outer element, the duplicate-ID
            // wrapping shape.
            let text: String = document.iter().collect();
            if text.contains("ID=\"resp\"") {
                *document = text
                    .replacen("ID=\"resp\"", "ID=\"a1\"", 1)
                    .chars()
                    .collect();
            }
        }
        4 => {
            // Truncate the document at the selected position.
            document.truncate(position);
        }
        _ => {
            // Smuggle an extra signature block (multi-target shape).
            let signature: Vec<char> = format!(
                "<ds:Signature \
                 xmlns:ds=\"{DS_NS}\"><ds:SignatureValue>AA</ds:SignatureValue></ds:Signature>"
            )
            .chars()
            .collect();
            document.splice(position..position, signature);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let seed = seed_document();
    let expected = verify_canonical(&seed).expect("seed must verify");
    let mut document: Vec<char> = seed.chars().collect();
    let mut cursor = 0;
    let mut edits = 0;
    while edits < 6 && cursor + 4 <= data.len() {
        let position = u16::from_le_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
        apply_edit(&mut document, data[cursor], position, data[cursor + 3]);
        cursor += 4;
        edits += 1;
    }
    let mutated: String = document.into_iter().collect();
    if mutated == seed {
        return;
    }
    if let Some(canonical) = verify_canonical(&mutated) {
        assert_eq!(
            canonical, expected,
            "wrapping bypass: mutated document verified with unexpected bytes"
        );
    }
});
