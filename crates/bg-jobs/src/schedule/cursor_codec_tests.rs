use super::{
    ScheduleControl, ScheduleControlResult, ScheduleCursor, constants::CATALOG_CURSOR_BYTES,
};
use crate::time::Timestamp;

#[test]
fn given_full_cursor_state_when_roundtripping_then_every_authority_field_is_preserved() {
    let cursor = ScheduleCursor {
        next_due: Some(Timestamp::from_millis(i64::MIN)),
        watermark: None,
        last_intended: Some(Timestamp::from_millis(7)),
        revision: u64::MAX,
        generation: u32::MAX,
        paused: true,
        enabled: false,
        active: true,
    };
    let encoded = cursor.encode_catalog_cursor();
    assert_eq!(encoded.len(), CATALOG_CURSOR_BYTES);
    assert_eq!(
        ScheduleCursor::decode_catalog_cursor(&encoded).unwrap(),
        cursor
    );
}

#[test]
fn given_malformed_cursor_when_decoding_then_truncation_flags_and_noncanonical_nulls_are_rejected()
{
    let encoded = ScheduleCursor::new(None, true).encode_catalog_cursor();
    for end in 0..encoded.len() {
        assert!(ScheduleCursor::decode_catalog_cursor(&encoded[..end]).is_err());
    }
    for index in [0, 9, 18, 39, 40, 41] {
        let mut invalid = encoded;
        invalid[index] = 2;
        assert!(ScheduleCursor::decode_catalog_cursor(&invalid).is_err());
    }
    let mut invalid = encoded;
    invalid[1] = 1;
    assert!(ScheduleCursor::decode_catalog_cursor(&invalid).is_err());
    let mut invalid = encoded.to_vec();
    invalid.push(0);
    assert!(ScheduleCursor::decode_catalog_cursor(&invalid).is_err());
}

#[test]
fn given_exhausted_cursor_authority_when_controlling_or_marking_then_it_remains_unchanged() {
    for (revision, generation) in [(u64::MAX, 0), (0, u32::MAX)] {
        let mut cursor = ScheduleCursor::new(Some(Timestamp::ZERO), true);
        cursor.revision = revision;
        cursor.generation = generation;
        let before = cursor.clone();
        assert!(matches!(
            cursor.apply_control(revision, generation, ScheduleControl::Pause),
            ScheduleControlResult::Conflict { .. }
        ));
        assert_eq!(cursor, before);
    }
    let mut cursor = ScheduleCursor::new(Some(Timestamp::ZERO), true);
    cursor.revision = u64::MAX;
    let before = cursor.clone();
    assert!(!cursor.mark_started(0, u64::MAX));
    assert_eq!(cursor, before);
    cursor.active = true;
    let before = cursor.clone();
    assert!(!cursor.mark_completed(0, u64::MAX));
    assert_eq!(cursor, before);
}
