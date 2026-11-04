use super::{
    constants::{ACTIVE_HEAD_BYTES, VACANT_HEAD_BYTES},
    state::{ActiveHead, Head, Phase},
};
use crate::{
    error::StoreDataError,
    ids::{CommitOperationId, LeaseToken},
};

fn active() -> Head {
    Head::Active(ActiveHead {
        generation: 17,
        command_id: CommitOperationId::from([1; 16]),
        token: LeaseToken::from([2; 16]),
        chunks: 1,
        input_bytes: 42,
        binding: [3; 32],
        phase: Phase::Prepared,
    })
}

#[test]
fn given_slot_heads_when_encoded_then_the_fixed_format_round_trips() {
    let Head::Active(pending) = active() else {
        unreachable!()
    };
    let completed = Head::Active(ActiveHead {
        chunks: 0,
        input_bytes: 0,
        phase: Phase::Committed,
        ..pending
    });
    for head in [Head::Vacant(0), Head::Vacant(u64::MAX), active(), completed] {
        let encoded = head.encode();
        assert!(matches!(
            encoded.len(),
            VACANT_HEAD_BYTES | ACTIVE_HEAD_BYTES
        ));
        assert!(Head::decode(&encoded).unwrap() == head);
    }
}

#[test]
fn given_invalid_slot_bytes_when_decoded_then_the_obligation_is_rejected_without_fallback() {
    let encoded = active().encode();
    for length in 0..encoded.len() {
        assert!(Head::decode(&encoded[..length]).is_err());
    }
    let mut unknown = encoded.to_vec();
    unknown[0] = 255;
    assert!(matches!(
        Head::decode(&unknown),
        Err(StoreDataError::UnknownVersion(255))
    ));
    let mut invalid = encoded.to_vec();
    invalid[82] = 255;
    assert!(Head::decode(&invalid).is_err());
    for phase in [Phase::Prepared, Phase::Committed, Phase::Conflict] {
        for (chunks, input_bytes) in [(0, 1), (1, 0), (0, 0)] {
            let Head::Active(pending) = active() else {
                unreachable!()
            };
            let invalid = Head::Active(ActiveHead {
                chunks,
                input_bytes,
                phase,
                ..pending
            });
            assert_eq!(
                Head::decode(&invalid.encode()).is_ok(),
                phase == Phase::Committed && chunks == 0 && input_bytes == 0
            );
        }
    }
}
