#![no_main]

use jwt_decode::{JwksDocument, dangerous_unverified_claims};
use libfuzzer_sys::fuzz_target;

// Token-shape and JWKS parsing must never panic on arbitrary input. Both
// entry points reject malformed input with typed errors; neither confers
// trust, so reaching `Ok` here carries no authorization meaning.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = dangerous_unverified_claims::<serde_json::Value>(text);
    let _ = JwksDocument::from_json_str(text);
});
