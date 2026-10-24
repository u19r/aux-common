#![cfg(all(feature = "tokio", unix))]

use std::{
    io::{BufRead, BufReader},
    os::unix::process::ExitStatusExt,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};

use serde_json::Value;

struct HostProcess {
    child: Child,
    events: Receiver<Value>,
    reader: Option<std::thread::JoinHandle<()>>,
}
impl HostProcess {
    fn start(grace: u64, delay: u64) -> Self {
        let binary = std::env::var("BUFFERED_WRITES_HOST_EXAMPLE")
            .expect("build persistent-host and select its binary explicitly");
        let mut child = Command::new(binary)
            .env("BUFFERED_WRITES_SHUTDOWN_GRACE_MS", grace.to_string())
            .env("BUFFERED_WRITES_DESTINATION_DELAY_MS", delay.to_string())
            .env("BUFFERED_WRITES_EXAMPLE_VALUE", "42")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, events) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let event: Value = serde_json::from_str(&line.unwrap()).unwrap();
                if sender.send(event).is_err() {
                    break;
                }
            }
        });
        let process = Self {
            child,
            events,
            reader: Some(reader),
        };
        let ready = process.event();
        assert_eq!(ready["event"], "ready");
        assert_eq!(ready["driver_active"], true);
        assert_eq!(ready["maximum"], 0, "young write should still be buffered");
        process
    }
    fn signal(&self, signal: &str) {
        assert!(
            Command::new("kill")
                .args([signal, &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }
    fn event(&self) -> Value {
        self.events.recv_timeout(Duration::from_secs(5)).unwrap()
    }
    fn exit(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "host did not exit after its bounded drain"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for HostProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
    }
}

#[test]
#[ignore = "requires a built persistent_host executable via BUFFERED_WRITES_HOST_EXAMPLE"]
fn given_native_term_when_young_write_is_buffered_then_drain_before_exit() {
    let mut host = HostProcess::start(1000, 0);
    host.signal("-TERM");
    let report = host.event();
    assert_eq!(report["event"], "drained");
    assert_eq!(report["clean"], true);
    assert_eq!(report["unresolved_items"], 0);
    assert_eq!(report["maximum"], 42);
    assert!(host.exit().success());
}

#[test]
#[ignore = "requires a built persistent_host executable via BUFFERED_WRITES_HOST_EXAMPLE"]
fn given_prestop_then_term_when_destination_hangs_then_share_original_deadline_and_report_unresolved()
 {
    let mut host = HostProcess::start(300, 2000);
    host.signal("-USR1");
    std::thread::sleep(Duration::from_millis(200));
    host.signal("-TERM");
    let report = host.event();
    assert_eq!(report["event"], "drained");
    assert_eq!(report["clean"], false);
    assert_eq!(report["unresolved_items"], 1);
    assert_eq!(report["maximum"], 0);
    assert!(
        report["elapsed_ms"].as_u64().unwrap() <= 350,
        "second signal must not renew the 300ms budget"
    );
    assert!(!host.exit().success());
}

#[test]
#[ignore = "requires a built persistent_host executable via BUFFERED_WRITES_HOST_EXAMPLE"]
fn given_native_kill_when_young_write_is_buffered_then_no_shutdown_callback_or_clean_report() {
    let mut host = HostProcess::start(1000, 0);
    host.child.kill().unwrap();
    assert_eq!(host.exit().signal(), Some(9));
    assert!(
        host.events
            .recv_timeout(Duration::from_millis(100))
            .is_err()
    );
}
