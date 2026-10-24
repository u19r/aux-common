#![no_main]

use chrono::{DateTime, Utc};
use libfuzzer_sys::fuzz_target;
use saml2::UnverifiedMetadata;

// Structured decision oracle for SAML metadata selection.
//
// Federation metadata arrives from counterparties, so every document byte
// is untrusted while the selected entity, endpoints, and certificates feed
// trust decisions. The oracle pins three properties: parsing never panics
// and is deterministic; selection is stable across re-parses; and validity
// is monotone in time — acceptance at a later instant implies acceptance
// at any earlier instant, so expired or not-yet-valid documents can never
// slip through a clock difference. Any violation confuses one metadata
// generation, entity, or validity window for another.
fn parse_at(document: &str, timestamp: i64) -> Option<(String, String, usize)> {
    let now = DateTime::<Utc>::from_timestamp(timestamp, 0)?;
    let metadata = UnverifiedMetadata::parse_unverified(document, now).ok()?;
    Some((
        metadata.entity_id().to_string(),
        metadata.sso_url().to_string(),
        metadata.certificates().len(),
    ))
}

fuzz_target!(|data: &[u8]| {
    let Ok(document) = std::str::from_utf8(data) else {
        return;
    };
    let early = parse_at(document, 946684800);
    let late = parse_at(document, 2051222400);
    let repeat = parse_at(document, 946684800);

    // Determinism: the same instant always selects the same projection.
    assert_eq!(early, repeat, "non-deterministic metadata selection");

    // Time monotonicity: acceptance later implies acceptance earlier, so
    // expiry can only narrow acceptance over time.
    if late.is_some() {
        assert!(
            early.is_some(),
            "metadata accepted after expiry but rejected before it"
        );
        assert_eq!(
            early, late,
            "metadata projection changed across its validity window"
        );
    }
});
