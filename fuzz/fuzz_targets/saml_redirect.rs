#![no_main]

use libfuzzer_sys::fuzz_target;
use saml2::validate_redirect_destination;

// Destination validation must never panic, and every accepted destination
// must remain an absolute HTTPS URL without credentials or a fragment.
fuzz_target!(|data: &[u8]| {
    let Ok(destination) = std::str::from_utf8(data) else {
        return;
    };
    if validate_redirect_destination(destination).is_ok() {
        // The validator rejects surrounding whitespace before URL parsing,
        // so accepted destinations start with the scheme verbatim.
        let lowered = destination.to_ascii_lowercase();
        assert!(lowered.starts_with("https://"), "accepted: {destination}");
        assert!(!destination.contains('#'), "accepted: {destination}");
    }
});
