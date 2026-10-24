use super::{LambdaWebEnvironment, LambdaWebRuntimeError};

#[test]
fn given_reserved_addresses_when_parsed_then_listen_and_shutdown_contracts_are_explicit() {
    let env = LambdaWebEnvironment::parse(Some("127.0.0.1:9000"), Some("127.0.0.1:9001"))
        .unwrap()
        .unwrap();
    assert_eq!(env.listen_address().to_string(), "127.0.0.1:9000");
    assert!(env.shutdown_grace() < std::time::Duration::from_secs(1));
    assert!(
        LambdaWebEnvironment::parse(Some("127.0.0.1:9000"), Some("127.0.0.1:80"))
            .unwrap()
            .is_some()
    );
    assert!(LambdaWebEnvironment::parse(None, None).unwrap().is_none());
}

#[test]
fn given_missing_or_credential_bearing_addresses_when_parsed_then_the_input_is_rejected_without_disclosure()
 {
    assert!(LambdaWebEnvironment::parse(Some("127.0.0.1:9000"), None).is_err());
    assert!(LambdaWebEnvironment::parse(None, Some("127.0.0.1:9001")).is_err());
    for address in [
        "127.0.0.1",
        "secret@127.0.0.1:9001",
        "127.0.0.1:9001/path",
        "127.0.0.1:9001?secret",
    ] {
        let result = LambdaWebEnvironment::parse(Some("127.0.0.1:9000"), Some(address));
        let error = result.err().unwrap();
        assert_eq!(error, LambdaWebRuntimeError::InvalidRuntimeAddress);
        assert!(!format!("{error:?}: {error}").contains("secret"));
    }
}
