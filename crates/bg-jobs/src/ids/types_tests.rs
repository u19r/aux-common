use crate::*;

#[test]
fn given_sixteen_bytes_when_constructing_each_fixed_identifier_then_the_bytes_round_trip() {
    let bytes = [0x5a; 16];

    assert_eq!(JobId::from(bytes).as_bytes(), &bytes);
    assert_eq!(ScheduleId::from(bytes).as_bytes(), &bytes);
    assert_eq!(OccurrenceId::from(bytes).as_bytes(), &bytes);
    assert_eq!(ExecutionId::from(bytes).as_bytes(), &bytes);
    assert_eq!(AttemptId::from(bytes).as_bytes(), &bytes);
    assert_eq!(LeaseToken::from(bytes).as_bytes(), &bytes);
    assert_eq!(OperationId::from(bytes).as_bytes(), &bytes);
    assert_eq!(CommitOperationId::from(bytes).as_bytes(), &bytes);
    assert_eq!(OwnerId::from(bytes).as_bytes(), &bytes);
}

#[test]
fn given_owned_or_borrowed_fixed_identifier_bytes_when_converting_then_length_is_checked() {
    let bytes = vec![0x5a; 16];
    assert_eq!(
        JobId::try_from(bytes.clone())
            .expect("owned bytes are valid")
            .into_bytes(),
        [0x5a; 16]
    );
    assert_eq!(
        JobId::try_from(bytes.as_slice())
            .expect("borrowed bytes are valid")
            .into_bytes(),
        [0x5a; 16]
    );
    assert!(JobId::try_from(vec![0; 15]).is_err());
}

#[test]
fn given_non_128_bit_input_when_parsing_fixed_identifiers_then_the_length_is_rejected() {
    for input in [[0u8; 15].as_slice(), [0u8; 17].as_slice()] {
        assert!(matches!(
            JobId::try_from_slice(input),
            Err(IdentifierError::InvalidLength {
                expected: 16,
                actual: 15 | 17,
                ..
            })
        ));
        assert!(ExecutionId::try_from_slice(input).is_err());
        assert!(AttemptId::try_from_slice(input).is_err());
        assert!(ScheduleId::try_from_slice(input).is_err());
        assert!(OccurrenceId::try_from_slice(input).is_err());
        assert!(LeaseToken::try_from_slice(input).is_err());
        assert!(OperationId::try_from_slice(input).is_err());
        assert!(CommitOperationId::try_from_slice(input).is_err());
        assert!(OwnerId::try_from_slice(input).is_err());
    }
}

#[test]
fn given_a_lease_token_when_debugging_it_then_secret_bytes_are_redacted() {
    let token = LeaseToken::from([0xa5; 16]);
    let debug = format!("{token:?}");

    assert_eq!(debug, "LeaseToken(redacted)");
    assert!(!debug.contains("a5"));
}

#[test]
fn given_opaque_text_and_scope_values_when_constructing_them_then_empty_and_control_values_fail() {
    assert!(matches!(
        JobKind::try_new(""),
        Err(IdentifierError::Empty { kind: "job kind" })
    ));
    assert!(matches!(
        QueueName::try_new("queue\nname"),
        Err(IdentifierError::InvalidText { kind: "queue name" })
    ));
    assert!(matches!(
        Namespace::try_new([]),
        Err(IdentifierError::Empty { kind: "namespace" })
    ));
}
