use serde::{Serialize, Serializer};
use serde_json::json;

use super::{
    JsBinding, JsError, JsInvocation, JsInvocationInput, JsSourceOrder, constants::*,
    executor::test_support::executor,
};

fn prepare(
    source: &str,
    function: &str,
    arguments: &impl Serialize,
    bindings: &[JsBinding<'_>],
) -> Result<super::JsJob, JsError> {
    let invocation = JsInvocation::try_new(JsInvocationInput {
        source,
        function,
        arguments,
        bindings,
        source_order: JsSourceOrder::BeforeBindings,
    })?;
    executor().prepare(invocation)
}
#[test]
fn given_invalid_names_when_preparing_then_rejected() {
    for name in [
        "",
        "1x",
        "x.y",
        "x()",
        "x;throw 1",
        "é",
        "a b",
        "this",
        "null",
        "class",
        "a\0b",
    ] {
        assert!(
            matches!(
                prepare("", name, &json!([]), &[]),
                Err(JsError::InvalidInvocation)
            ),
            "{name:?}"
        );
        assert!(matches!(
            prepare(
                "",
                "apply",
                &json!([1]),
                &[JsBinding {
                    name,
                    argument_index: 0
                }]
            ),
            Err(JsError::InvalidInvocation)
        ));
    }
    assert!(matches!(
        prepare("", &"x".repeat(MAX_IDENTIFIER_BYTES + 1), &json!([]), &[]),
        Err(JsError::InvalidInvocation)
    ));
    assert!(prepare("", &"x".repeat(MAX_IDENTIFIER_BYTES), &json!([]), &[]).is_ok());
}
#[test]
fn given_invalid_argument_and_binding_shapes_when_preparing_then_rejected() {
    for arguments in [json!({}), json!(null), json!(1), json!(vec![0; 17])] {
        assert!(matches!(
            prepare("", "apply", &arguments, &[]),
            Err(JsError::InvalidInvocation)
        ));
    }
    for bindings in [
        vec![JsBinding {
            name: "x",
            argument_index: 1,
        }],
        vec![
            JsBinding {
                name: "x",
                argument_index: 0,
            },
            JsBinding {
                name: "x",
                argument_index: 0,
            },
        ],
    ] {
        assert!(matches!(
            prepare("", "apply", &json!([1]), &bindings),
            Err(JsError::InvalidInvocation)
        ));
    }
    let names = (0..17).map(|n| format!("x{n}")).collect::<Vec<_>>();
    let bindings = names
        .iter()
        .map(|name| JsBinding {
            name,
            argument_index: 0,
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        prepare("", "apply", &json!([1]), &bindings),
        Err(JsError::InvalidInvocation)
    ));
    assert!(prepare("", "apply", &json!(vec![0; 16]), &bindings[..16]).is_ok());
}
#[test]
fn given_source_and_argument_limits_when_preparing_then_exact_boundaries_hold() {
    assert!(prepare(&" ".repeat(MAX_SOURCE_BYTES), "apply", &json!([]), &[]).is_ok());
    assert!(matches!(
        prepare(&" ".repeat(MAX_SOURCE_BYTES + 1), "apply", &json!([]), &[]),
        Err(JsError::SourceTooLarge)
    ));
    assert!(
        prepare(
            "",
            "apply",
            &json!(["x".repeat(MAX_ARGUMENT_BYTES - 2)]),
            &[]
        )
        .is_ok()
    );
    assert!(matches!(
        prepare(
            "",
            "apply",
            &json!(["x".repeat(MAX_ARGUMENT_BYTES - 1)]),
            &[]
        ),
        Err(JsError::InputTooLarge)
    ));
    assert!(matches!(
        prepare(
            "",
            "apply",
            &json!(["\u{1}".repeat(MAX_ARGUMENT_BYTES / 6 + 1)]),
            &[]
        ),
        Err(JsError::InputTooLarge)
    ));
    let job = prepare(
        &"\u{1}".repeat(MAX_SOURCE_BYTES),
        "apply",
        &json!(["x".repeat(MAX_ARGUMENT_BYTES - 2)]),
        &[],
    )
    .unwrap();
    assert!(job.wire.len() < MAX_JOB_BYTES);
}
struct FailingSerializer;
impl Serialize for FailingSerializer {
    fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom("customer_secret"))
    }
}
#[test]
fn given_serializer_failure_when_preparing_then_fixed_error_hides_customer_bytes() {
    let error = prepare("", "apply", &FailingSerializer, &[]).err().unwrap();
    assert_eq!(error, JsError::InvalidInvocation);
    assert_eq!(
        format!("{error} {error:?}"),
        "InvalidInvocation InvalidInvocation"
    );
}
