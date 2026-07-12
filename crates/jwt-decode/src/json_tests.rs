use crate::json::JsonDocument;

#[test]
fn given_trailing_json_value_when_validating_document_then_rejects_input() {
    assert!(JsonDocument::reject_duplicate_members(br#"{} {}"#).is_err());
}

#[test]
fn given_trailing_json_value_when_parsing_document_then_rejects_input() {
    assert!(JsonDocument::value_rejecting_duplicate_members(br#"{} []"#).is_err());
}

#[test]
fn given_trailing_whitespace_when_parsing_document_then_accepts_input() {
    assert!(JsonDocument::reject_duplicate_members(b"{} \n\t").is_ok());
    assert!(JsonDocument::value_rejecting_duplicate_members(b"{} \n\t").is_ok());
}
