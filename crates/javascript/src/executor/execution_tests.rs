use std::{
    thread,
    time::{Duration, Instant},
};

use serde_json::json;

use super::test_support::{evaluate, evaluate_result_contract, executor};
use crate::{
    JsBinding, JsCancellation, JsError, JsInvocation, JsInvocationInput, JsSourceOrder,
    constants::*,
};

#[test]
fn given_explicit_arguments_when_running_business_function_then_expected_json_returned() {
    let value = evaluate("function apply(a,b){return a+b}", (2, 3)).unwrap();
    assert_eq!(value.get(), "5");
    let source = "function apply(ctx,req){req.headers['X-Test']=ctx.trace_id;req.body={ok:true,\
                  original:req.body};return req;}";
    let value = evaluate(
        source,
        (
            json!({"trace_id":"trace"}),
            json!({"headers":{},"body":{"value":1}}),
        ),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(value.get()).unwrap(),
        json!({"headers":{"X-Test":"trace"},"body":{"ok":true,"original":{"value":1}}})
    );
    let value = evaluate(
        "function apply(ctx,req,resp){return resp.body.result}",
        (json!({}), json!({}), json!({"body":{"result":{"ok":true}}})),
    )
    .unwrap();
    assert_eq!(value.get(), r#"{"ok":true}"#);
    assert_eq!(
        evaluate(
            "function apply(req){return {allow:req.enabled}}",
            (json!({"enabled":false}),)
        )
        .unwrap()
        .get(),
        r#"{"allow":false}"#
    );
}
#[test]
fn given_aliases_and_loading_order_when_running_then_argument_identity_is_preserved() {
    let bindings = [JsBinding {
        name: "alias",
        argument_index: 0,
    }];
    for (order, expected) in [
        (JsSourceOrder::BeforeBindings, "undefined"),
        (JsSourceOrder::AfterBindings, "object"),
    ] {
        let invocation = JsInvocation::try_new(JsInvocationInput {
            source: "let seen=typeof alias; function apply(req){alias.updated=true; return \
                     [seen,alias===req,req.updated];}",
            function: "apply",
            arguments: (json!({}),),
            bindings: &bindings,
            source_order: order,
        })
        .unwrap();
        let value = executor()
            .run(
                executor().prepare(invocation).unwrap(),
                JsCancellation::new(),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(value.get()).unwrap(),
            json!([expected, true, true])
        );
    }
}
#[test]
fn given_invalid_scripts_and_results_when_running_then_fixed_failure_categories() {
    for (source, expected) in [
        ("function other(){}", JsError::ScriptFailed),
        ("function apply( {", JsError::ScriptFailed),
        (
            "function apply(){throw new Error('customer_secret')}",
            JsError::ScriptFailed,
        ),
        ("function apply(){return undefined}", JsError::InvalidOutput),
        (
            "function apply(){let a={};a.self=a;return a}",
            JsError::InvalidOutput,
        ),
        (
            "function apply(){return function(){}}",
            JsError::InvalidOutput,
        ),
        (
            "function apply(){return {toJSON(){throw 1}}}",
            JsError::InvalidOutput,
        ),
    ] {
        assert_eq!(
            evaluate(source, json!([])).err(),
            Some(expected),
            "{source}"
        );
    }
}
#[test]
fn given_result_size_boundary_when_running_guest_then_exact_limit_succeeds_and_next_byte_is_rejected()
 {
    assert_eq!(
        evaluate_result_contract("function apply(){return 'x'.repeat(262142)}", json!([]))
            .unwrap()
            .get()
            .len(),
        MAX_RESULT_BYTES
    );
    assert_eq!(
        evaluate_result_contract("function apply(){return 'x'.repeat(262143)}", json!([])).err(),
        Some(JsError::OutputTooLarge)
    );
}

#[test]
fn given_guest_mutation_when_running_next_job_then_state_and_prototypes_are_fresh() {
    assert_eq!(
        evaluate(
            "function apply(){globalThis.secret='customer';Object.prototype.secret='prototype';\
             Math.abs=()=>99;return true}",
            json!([])
        )
        .unwrap()
        .get(),
        "true"
    );
    assert_eq!(
        evaluate(
            "function apply(){return [typeof globalThis.secret,typeof ({}).secret,Math.abs(-1)]}",
            json!([])
        )
        .unwrap()
        .get(),
        r#"["undefined","undefined",1]"#
    );
}
#[test]
fn given_cpu_explosion_when_running_then_timeout_and_next_job_recovers() {
    executor();
    for source in [
        "while(true){};function apply(){}",
        "function apply(){while(true){}}",
        "function apply(){return {toJSON(){while(true){}}}}",
    ] {
        let started = Instant::now();
        assert_eq!(evaluate(source, json!([])).err(), Some(JsError::Timeout));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(
            evaluate("function apply(){return 7}", json!([]))
                .unwrap()
                .get(),
            "7"
        );
    }
}
#[test]
fn given_memory_explosion_when_running_then_bounded_failure_and_next_job_recovers() {
    executor();
    for source in [
        "function apply(){let a=[];while(true){a.push('x'.repeat(1000000));}}",
        "function apply(){return 'x'.repeat(1000000000)}",
        "function apply(){return apply()}",
    ] {
        let started = Instant::now();
        // The absolute deadline may interrupt allocation or recursion before
        // its ceiling.
        assert!(matches!(
            evaluate(source, json!([])),
            Err(JsError::ResourceLimit | JsError::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(
            evaluate("function apply(){return 8}", json!([]))
                .unwrap()
                .get(),
            "8"
        );
    }
}
#[test]
fn given_wasm_stack_exhaustion_when_calling_guest_then_stack_overflow_traps() {
    let engine = super::module::create_engine().unwrap();
    let wasm = wat::parse_str(
        "(module (func $recurse (export \"run\") (result i32) call $recurse i32.const 1 i32.add))",
    )
    .unwrap();
    let module = wasmtime::Module::new(&engine, wasm).unwrap();
    let mut store = wasmtime::Store::new(&engine, ());
    store.set_fuel(JOB_FUEL).unwrap();
    // Isolate the configured stack ceiling from the independent
    // deadline/ticker.
    store.set_epoch_deadline(u64::MAX);
    let instance = wasmtime::Instance::new(&mut store, &module, &[]).unwrap();
    let error = instance
        .get_typed_func::<(), i32>(&mut store, "run")
        .unwrap()
        .call(&mut store, ())
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<wasmtime::Trap>(),
        Some(&wasmtime::Trap::StackOverflow)
    );
}
#[test]
fn given_cancelled_and_running_jobs_when_cancelling_then_stops_and_recovers() {
    let make_job = || {
        executor().prepare(
            JsInvocation::try_new(JsInvocationInput {
                source: "function apply(){while(true){}}",
                function: "apply",
                arguments: (),
                bindings: &[],
                source_order: JsSourceOrder::BeforeBindings,
            })
            .unwrap(),
        )
    };
    // Empty tuple is null, not an argument array. Use an explicit empty array.
    assert!(matches!(make_job(), Err(JsError::InvalidInvocation)));
    let make_job = || {
        executor()
            .prepare(
                JsInvocation::try_new(JsInvocationInput {
                    source: "function apply(){while(true){}}",
                    function: "apply",
                    arguments: json!([]),
                    bindings: &[],
                    source_order: JsSourceOrder::BeforeBindings,
                })
                .unwrap(),
            )
            .unwrap()
    };
    let cancelled = JsCancellation::new();
    cancelled.cancel();
    assert_eq!(
        executor().run(make_job(), cancelled).err(),
        Some(JsError::Cancelled)
    );
    let cancellation = JsCancellation::new();
    let job = make_job();
    let signal = cancellation.clone();
    let task = thread::spawn(move || executor().run(job, signal));
    thread::sleep(Duration::from_millis(5));
    cancellation.cancel();
    // Scheduler delay can let the absolute deadline finish before this signal.
    assert!(matches!(
        task.join().unwrap(),
        Err(JsError::Cancelled | JsError::Timeout)
    ));
    assert_eq!(
        evaluate("function apply(){return 9}", json!([]))
            .unwrap()
            .get(),
        "9"
    );
}
#[test]
fn given_concurrent_jobs_when_running_then_arguments_and_state_do_not_leak() {
    thread::scope(|scope| {
        let tasks = (0..4)
            .map(|id| {
                scope.spawn(move || {
                    let result = evaluate(
                        "function apply(id){if(typeof secret!=='undefined')throw \
                         1;globalThis.secret=id;return id}",
                        (id,),
                    )
                    .unwrap();
                    assert_eq!(result.get(), id.to_string());
                })
            })
            .collect::<Vec<_>>();
        for task in tasks {
            task.join().unwrap();
        }
    });
}
#[test]
fn given_host_sentinels_when_checking_ambient_apis_then_only_explicit_data_is_visible() {
    let private_file =
        std::env::temp_dir().join(format!("javascript-private-{}", std::process::id()));
    std::fs::write(&private_file, b"host_only_file_sentinel").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let host_sentinel = std::env::var("PATH").unwrap();
    let apis = [
        "process",
        "require",
        "fetch",
        "std",
        "os",
        "console",
        "Date",
        "performance",
        "SharedArrayBuffer",
        "Math.random",
        "Promise",
        "ArrayBuffer",
        "Uint8Array",
        "WebAssembly",
    ];
    let source = format!(
        "function apply(data){{return [{}]}}",
        apis.iter()
            .map(|api| format!("typeof {api}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let result = evaluate(&source, (json!({"path":private_file,"listener":listener.local_addr().unwrap().to_string(),"metadata":"http://169.254.169.254/latest/meta-data/"}),)).unwrap();
    assert_eq!(
        serde_json::from_str::<Vec<String>>(result.get()).unwrap(),
        vec!["undefined"; apis.len()]
    );
    assert!(!result.get().contains(&host_sentinel));
    assert!(
        matches!(listener.accept(), Err(error) if error.kind()==std::io::ErrorKind::WouldBlock)
    );
    assert_eq!(
        std::fs::read(&private_file).unwrap(),
        b"host_only_file_sentinel"
    );
    std::fs::remove_file(private_file).unwrap();
}

#[test]
fn given_untrusted_wire_documents_when_guest_revalidates_then_invalid_job_is_rejected() {
    use super::{
        execution::execute_module, imports::restricted_linker, module::embedded_module,
        state::JobState, test_support::hostile_engine,
    };
    use crate::JsJob;
    let engine = hostile_engine();
    let module = embedded_module(engine).unwrap();
    let linker = restricted_linker(engine).unwrap();
    let valid = r#"{"version":1,"source":"function apply(){return null}","function":"apply","arguments":[],"bindings":[],"source_order":"before_bindings"}"#;
    let mutations = [
        format!("{valid} null"),
        valid.replace("\"version\":1", "\"version\":2"),
        valid.replace("\"function\":\"apply\"", "\"function\":\"apply()\""),
        valid.replace("\"arguments\":[]", "\"arguments\":{}"),
        valid.replace(
            "\"bindings\":[]",
            "\"bindings\":[{\"name\":\"x\",\"argument_index\":0}]",
        ),
        valid.replace(
            "\"source_order\":\"before_bindings\"",
            "\"source_order\":\"unexpected\"",
        ),
        valid.replace("\"version\":1", "\"extra\":1,\"version\":1"),
        valid.replace(
            "function apply(){return null}",
            &" ".repeat(MAX_SOURCE_BYTES + 1),
        ),
        valid.replace(
            "\"arguments\":[]",
            &format!("\"arguments\":[\"{}\"]", "x".repeat(MAX_ARGUMENT_BYTES)),
        ),
        " ".repeat(MAX_JOB_BYTES + 1),
    ];
    for wire in mutations {
        assert_eq!(
            execute_module(
                &module,
                &linker,
                JobState::new(
                    JsJob {
                        wire: wire.into_bytes()
                    },
                    JsCancellation::new()
                )
            )
            .err(),
            Some(JsError::InvalidInvocation)
        );
    }
    assert_eq!(
        execute_module(
            &module,
            &linker,
            JobState::new(
                JsJob {
                    wire: valid.as_bytes().to_vec()
                },
                JsCancellation::new()
            )
        )
        .unwrap()
        .get(),
        "null"
    );
}
