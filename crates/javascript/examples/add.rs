//! No storage, tenant identity or async runtime is needed.
#![forbid(unsafe_code)]
use javascript::{JsCancellation, JsExecutor, JsInvocation, JsInvocationInput, JsSourceOrder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let executor = JsExecutor::try_new()?;
    let invocation = JsInvocation::try_new(JsInvocationInput {
        source: "function add(a, b) { return a + b; }",
        function: "add",
        arguments: (2, 3),
        bindings: &[],
        source_order: JsSourceOrder::BeforeBindings,
    })?;
    let value = executor.run(executor.prepare(invocation)?, JsCancellation::new())?;
    assert_eq!(value.get(), "5");
    println!("{}", value.get());
    Ok(())
}
