use syn::{LitStr, Meta, Token, parse::Parser, punctuated::Punctuated};

use super::parse_label;

fn parse_args(source: &str) -> Punctuated<Meta, Token![,]> {
    match Punctuated::<Meta, Token![,]>::parse_terminated.parse_str(source) {
        Ok(args) => args,
        Err(error) => panic!("test arguments should parse: {error}"),
    }
}

#[test]
fn given_string_label_when_parsed_then_returns_label() {
    let label = match parse_label(parse_args("label = \"baseline\"")) {
        Ok(label) => label,
        Err(error) => panic!("string label should be accepted: {error}"),
    };

    assert_eq!(
        label.as_ref().map(LitStr::value),
        Some("baseline".to_owned())
    );
}

#[test]
fn given_unsupported_argument_when_parsed_then_returns_error() {
    let error = match parse_label(parse_args("name = \"baseline\"")) {
        Ok(_) => panic!("unsupported argument should be rejected"),
        Err(error) => error,
    };

    assert_eq!(
        error.to_string(),
        "unsupported argument, expected `label = \"...\"`",
    );
}

#[test]
fn given_non_string_label_when_parsed_then_returns_error() {
    let error = match parse_label(parse_args("label = 42")) {
        Ok(_) => panic!("non-string label should be rejected"),
        Err(error) => error,
    };

    assert_eq!(
        error.to_string(),
        "`label` must be a string literal, for example: label = \"baseline\"",
    );
}

#[test]
fn given_duplicate_labels_when_parsed_then_returns_error() {
    let error = match parse_label(parse_args("label = \"one\", label = \"two\"")) {
        Ok(_) => panic!("duplicate labels should be rejected"),
        Err(error) => error,
    };

    assert_eq!(error.to_string(), "duplicate `label` argument");
}
