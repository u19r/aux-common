#![no_main]

use libfuzzer_sys::fuzz_target;
use xml_security::{UnverifiedElement, XmlLimits};

// The bounded XML parser and canonicalizer must never panic on arbitrary
// input, and canonicalization of a successfully parsed document must be
// deterministic.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(element) = UnverifiedElement::parse_unverified_with_limits(text, XmlLimits::default())
    else {
        return;
    };
    let Ok(first) = element.canonicalize_unverified() else {
        return;
    };
    let Ok(second) = element.canonicalize_unverified() else {
        return;
    };
    assert_eq!(first, second);
});
