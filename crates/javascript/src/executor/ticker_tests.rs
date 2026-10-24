use std::{
    thread,
    time::{Duration, Instant},
};

use wasmtime::{Module, Store};

use super::{
    execution::execute_module, imports::restricted_linker, module::create_engine, state::JobState,
    ticker::EpochTicker,
};
use crate::{JsCancellation, JsError, JsJob, constants::JOB_FUEL};

#[test]
fn given_running_guest_when_cancelled_at_epoch_then_typed_cancellation_stops_execution() {
    let engine = create_engine().unwrap();
    let wasm = wat::parse_str(r#"(module (func (export "_start") (loop br 0)))"#).unwrap();
    let module = Module::new(&engine, wasm).unwrap();
    let state = JobState::new(JsJob { wire: vec![] }, JsCancellation::new());
    let mut store = Store::new(&engine, state);
    store.set_fuel(JOB_FUEL).unwrap();
    store.set_epoch_deadline(1);
    // Trigger the signal from the running guest's epoch callback. No host
    // scheduling race or production test hook is needed.
    store.epoch_deadline_callback(|store| {
        store.data().cancellation.cancel();
        store.data().check_interrupt()?;
        Ok(wasmtime::UpdateDeadline::Continue(1))
    });
    let instance = restricted_linker(&engine)
        .unwrap()
        .instantiate(&mut store, &module)
        .unwrap();
    engine.increment_epoch();
    let error = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .unwrap()
        .call(&mut store, ())
        .unwrap_err();
    assert_eq!(error.downcast_ref::<JsError>(), Some(&JsError::Cancelled));
}

#[test]
fn given_stopped_ticker_when_fuel_exhausts_then_timeout_without_epoch_dependency() {
    let engine = create_engine().unwrap();
    let wasm = wat::parse_str(r#"(module (func (export "_start") (loop br 0)))"#).unwrap();
    let module = Module::new(&engine, wasm).unwrap();
    let started = cpu_time::ThreadTime::now();
    assert_eq!(
        execute_module(
            &module,
            &restricted_linker(&engine).unwrap(),
            JobState::new(JsJob { wire: vec![] }, JsCancellation::new())
        )
        .err(),
        Some(JsError::Timeout)
    );
    let cpu_time = started.elapsed();
    assert!(
        cpu_time < Duration::from_secs(5),
        "fuel exhaustion must bound guest CPU work: {cpu_time:?}"
    );
}
#[test]
fn given_expired_absolute_deadline_when_epoch_resumes_then_interrupts_immediately() {
    let engine = create_engine().unwrap();
    let wasm = wat::parse_str(r#"(module (func (export "_start") (loop br 0)))"#).unwrap();
    let module = Module::new(&engine, wasm).unwrap();
    let mut state = JobState::new(JsJob { wire: vec![] }, JsCancellation::new());
    state.deadline = Instant::now() - Duration::from_millis(1);
    let mut store = Store::new(&engine, state);
    store.set_fuel(JOB_FUEL).unwrap();
    store.set_epoch_deadline(1);
    store.epoch_deadline_callback(|store| {
        store.data().check_interrupt()?;
        Ok(wasmtime::UpdateDeadline::Continue(1))
    });
    let instance = restricted_linker(&engine)
        .unwrap()
        .instantiate(&mut store, &module)
        .unwrap();
    engine.increment_epoch();
    let error = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .unwrap()
        .call(&mut store, ())
        .unwrap_err();
    assert_eq!(error.downcast_ref::<JsError>(), Some(&JsError::Timeout));
    // A newly submitted job must receive a fresh absolute deadline even after
    // delay.
    thread::sleep(Duration::from_millis(60));
    assert!(
        JobState::new(JsJob { wire: vec![] }, JsCancellation::new())
            .check_interrupt()
            .is_ok()
    );
}
#[test]
fn given_idle_ticker_when_dropping_then_thread_is_joined_promptly() {
    let engine = create_engine().unwrap();
    for _ in 0..4 {
        let ticker = EpochTicker::try_new(engine.clone()).unwrap();
        thread::sleep(Duration::from_millis(2));
        let started = Instant::now();
        drop(ticker);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
