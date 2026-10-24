use crate::{FairScope, FairnessClass, FairnessKey, FairnessPath, IdentifierError};

#[test]
fn given_primary_fairness_bytes_when_constructing_a_path_then_secondary_is_optional() {
    let primary = FairnessKey::try_new([0x01]).expect("one-byte primary is valid");
    let path = FairnessPath::new(primary.clone(), None);

    assert_eq!(path.primary, primary);
    assert_eq!(path.secondary, None);
    assert_eq!(
        FairnessClass::from(path.clone()),
        FairnessClass::Scoped(path)
    );
    assert_eq!(FairnessClass::low_volume(), FairnessClass::LowVolume);
}

#[test]
fn given_fairness_key_lengths_when_constructing_the_key_then_only_one_to_128_bytes_are_valid() {
    let one = FairnessKey::try_new([0x01]).expect("one byte is valid");
    let maximum = FairnessKey::try_new([0x02; FairnessKey::MAX_BYTES])
        .expect("the 128-byte boundary is valid");
    let empty = FairnessKey::try_new([]);
    let too_long = FairnessKey::try_new([0x03; FairnessKey::MAX_BYTES + 1]);

    assert_eq!(one.as_bytes(), &[0x01]);
    assert_eq!(maximum.as_bytes().len(), FairnessKey::MAX_BYTES);
    assert!(matches!(empty, Err(IdentifierError::Empty { .. })));
    assert!(matches!(
        too_long,
        Err(IdentifierError::TooLong { maximum: 128, .. })
    ));
}

#[test]
fn given_distinct_primary_and_secondary_values_when_constructing_a_path_then_the_parts_remain_distinct()
 {
    let primary = FairnessKey::try_new([0x10, 0x00]).expect("primary is valid");
    let secondary = FairnessKey::try_new([0x10]).expect("secondary is valid");
    let path = FairnessPath::new(primary.clone(), Some(secondary.clone()));

    assert_eq!(path.primary, primary);
    assert_eq!(path.secondary, Some(secondary.clone()));
    let FairnessPath {
        primary: decoded_primary,
        secondary: decoded_secondary,
    } = path;
    assert_eq!(decoded_primary, primary);
    assert_eq!(decoded_secondary, Some(secondary));
}

#[test]
fn given_fairness_class_when_converting_owned_or_borrowed_then_scope_is_identical() {
    let primary = FairnessKey::try_new([0x20]).expect("primary is valid");
    let secondary = FairnessKey::try_new([0x21]).expect("secondary is valid");
    let scoped = FairnessClass::from(FairnessPath::new(primary, Some(secondary)));

    assert_eq!(FairScope::from(&scoped), FairScope::from(scoped.clone()));
    assert_eq!(
        FairScope::from(&FairnessClass::LowVolume),
        FairScope::from(FairnessClass::LowVolume),
    );
}
