use super::{JsError, protocol::GuestJob};

#[test]
fn given_malformed_guest_documents_when_decoding_then_rejected() {
    let valid = r#"{"version":1,"source":"","function":"apply","arguments":[],"bindings":[],"source_order":"before_bindings"}"#;
    for document in [
        format!("{valid} null"),
        valid.replace("1,", "1,\"extra\":0,"),
        valid.replace("\"arguments\":[]", "\"arguments\":{}"),
        valid.replace(
            "\"bindings\":[]",
            "\"bindings\":[{\"name\":\"x\",\"argument_index\":0,\"extra\":0}]",
        ),
        valid.replace("\"version\":1", "\"version\":1,\"version\":1"),
    ] {
        assert!(
            serde_json::from_str::<GuestJob>(&document).is_err(),
            "{document}"
        );
    }
    for document in [
        valid.replace("\"version\":1", "\"version\":2"),
        valid.replace("\"function\":\"apply\"", "\"function\":\"x()\""),
        valid.replace(
            "\"bindings\":[]",
            "\"bindings\":[{\"name\":\"x\",\"argument_index\":0}]",
        ),
    ] {
        assert_eq!(
            serde_json::from_str::<GuestJob>(&document)
                .unwrap()
                .validate(),
            Err(JsError::InvalidInvocation)
        );
    }
    assert!(
        serde_json::from_str::<GuestJob>(valid)
            .unwrap()
            .validate()
            .is_ok()
    );
}

#[test]
fn given_raw_success_values_and_mixed_failure_fields_when_decoding_then_schema_is_exact() {
    use super::protocol::{GuestReply, GuestResult};
    for value in ["null", "5", "false", r#"{"nested":[1,2]}"#] {
        let reply = format!(r#"{{"version":1,"result":{{"type":"success","value":{value}}}}}"#);
        let decoded: GuestReply = serde_json::from_str(&reply).unwrap();
        let GuestResult::Success { value: decoded } = decoded.result else {
            panic!("expected success");
        };
        assert_eq!(decoded.get(), value);
    }
    for result in [
        r#"{"type":"success","value":null,"code":null}"#,
        r#"{"type":"failure","value":null,"code":"script_failed"}"#,
        r#"{"type":"success"}"#,
        r#"{"type":"failure","code":null}"#,
    ] {
        assert!(
            serde_json::from_str::<GuestReply>(&format!(r#"{{"version":1,"result":{result}}}"#))
                .is_err()
        );
    }
}
