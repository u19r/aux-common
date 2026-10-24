use std::collections::BTreeMap;

use super::{RenderedValue, parse};

#[test]
fn given_rendered_scalars_when_parsed_then_values_are_preserved() {
    assert_eq!(parse(" true ").unwrap(), RenderedValue::Bool(true));
    assert_eq!(parse("false").unwrap(), RenderedValue::Bool(false));
    assert_eq!(parse("-42").unwrap(), RenderedValue::Integer(-42));
    assert_eq!(
        parse(r#""quoted\" text""#).unwrap(),
        RenderedValue::Text("quoted\" text".to_string())
    );
    assert_eq!(
        parse("Node_A-1").unwrap(),
        RenderedValue::Atom("Node_A-1".to_string())
    );
}

#[test]
fn given_rendered_list_syntax_when_parsed_then_nested_tuples_are_preserved() {
    assert_eq!(
        parse(r#"(true, -7, (NodeA, "text"))"#).unwrap(),
        RenderedValue::Tuple(vec![
            RenderedValue::Bool(true),
            RenderedValue::Integer(-7),
            RenderedValue::Tuple(vec![
                RenderedValue::Atom("NodeA".to_string()),
                RenderedValue::Text("text".to_string()),
            ]),
        ])
    );
    assert_eq!(parse("()").unwrap(), RenderedValue::Tuple(Vec::new()));
}

#[test]
fn given_rendered_record_syntax_when_parsed_then_fields_are_structured() {
    let fields = BTreeMap::from([
        ("enabled".to_string(), RenderedValue::Bool(true)),
        (
            "items".to_string(),
            RenderedValue::Tuple(vec![RenderedValue::Integer(1), RenderedValue::Integer(2)]),
        ),
    ]);
    assert_eq!(
        parse("{ enabled: true, items: (1, 2) }").unwrap(),
        RenderedValue::Record(fields)
    );
}

#[test]
fn given_duplicate_rendered_record_fields_when_parsed_then_the_value_is_rejected() {
    assert!(parse("{ value: 1, value: 2 }").is_err());
}

#[test]
fn given_whitespace_after_variant_opening_when_parsed_then_payload_is_preserved() {
    assert_eq!(
        parse("Some( 42 )").unwrap(),
        RenderedValue::Variant("Some".to_string(), Box::new(RenderedValue::Integer(42)))
    );
    assert_eq!(
        parse("Pair( true, NodeA )").unwrap(),
        RenderedValue::Variant(
            "Pair".to_string(),
            Box::new(RenderedValue::Tuple(vec![
                RenderedValue::Bool(true),
                RenderedValue::Atom("NodeA".to_string()),
            ])),
        )
    );
    assert_eq!(
        parse("Empty( )").unwrap(),
        RenderedValue::Variant(
            "Empty".to_string(),
            Box::new(RenderedValue::Tuple(Vec::new()))
        )
    );
}

#[test]
fn given_integer_boundaries_when_parsed_then_i64_values_are_preserved() {
    assert_eq!(
        parse(&i64::MAX.to_string()).unwrap(),
        RenderedValue::Integer(i64::MAX)
    );
    assert_eq!(
        parse(&i64::MIN.to_string()).unwrap(),
        RenderedValue::Integer(i64::MIN)
    );
}

#[test]
fn given_out_of_bounds_numbers_when_parsed_then_they_are_rejected() {
    assert!(parse("9223372036854775808").is_err());
    assert!(parse("-9223372036854775809").is_err());
    assert!(parse("-").is_err());
}

#[test]
fn given_malformed_rendered_values_when_parsed_then_they_are_rejected() {
    for value in [
        "",
        "true trailing",
        "{ value: }",
        "(1,)",
        "Some(1",
        "\"unterminated",
        "{ value: 1,}",
        "Some(, 1)",
    ] {
        assert!(parse(value).is_err(), "accepted malformed value {value:?}");
    }
}
