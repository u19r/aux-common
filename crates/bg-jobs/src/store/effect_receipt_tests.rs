use super::{EffectReceiptGroup, EffectReceiptKind};
use crate::{
    codec::{KeyCodec, KeyTag},
    ids::{ExecutionId, JobId, Namespace},
};

fn namespace() -> Namespace {
    Namespace::try_new(b"ns").expect("test namespace is valid")
}

fn group(execution: u8) -> EffectReceiptGroup {
    EffectReceiptGroup::new(
        &namespace(),
        JobId::from([1; 16]),
        ExecutionId::from([execution; 16]),
    )
    .expect("test group is valid")
}

#[test]
fn given_group_when_building_member_keys_then_each_kind_is_inside_prefix_and_below_end() {
    let group = group(2);
    let effect = group
        .member_key(EffectReceiptKind::Effect, &[7; 32])
        .expect("effect member key is valid");
    let projection = group
        .member_key(EffectReceiptKind::TerminalProjection, &[7; 32])
        .expect("projection member key is valid");
    for key in [&effect, &projection] {
        assert!(group.contains(key));
        assert!(group.prefix() < key);
        assert!(key < group.end());
    }
    assert_ne!(effect, projection);
}

#[test]
fn given_two_executions_of_one_job_when_building_groups_then_ranges_do_not_overlap() {
    let first = group(2);
    let second = group(3);
    for kind in [
        EffectReceiptKind::Effect,
        EffectReceiptKind::TerminalProjection,
    ] {
        let member = first.member_key(kind, &[7; 32]).unwrap();
        assert!(!second.contains(&member));
    }
    assert!(first.end() <= second.prefix());
}

#[test]
fn given_member_key_when_decoding_then_tag_and_components_round_trip() {
    let group = group(2);
    let key = group
        .member_key(EffectReceiptKind::TerminalProjection, &[7; 32])
        .unwrap();
    let decoded = KeyCodec::decode(&namespace(), &key).unwrap();
    assert_eq!(decoded.tag, KeyTag::EffectReceipt);
    assert_eq!(decoded.components.len(), 3);
    assert_eq!(decoded.components[0], [1; 16].to_vec());
    assert_eq!(decoded.components[1], [2; 16].to_vec());
    assert_eq!(decoded.components[2].len(), 33);
    assert_eq!(
        decoded.components[2][0],
        EffectReceiptKind::TerminalProjection as u8
    );
    assert_eq!(decoded.components[2][1..], [7; 32]);
}

#[test]
fn given_effect_receipt_tag_byte_when_parsing_then_tag_is_effect_receipt() {
    assert_eq!(KeyTag::try_from_byte(b'Y'), Ok(KeyTag::EffectReceipt));
}
