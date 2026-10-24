use std::{io::Write, sync::atomic::Ordering};

use buffered_writes::{
    BufferedWrites, Deadline, DrainReport, Lifecycle, RuntimeGuard, TokioLifecycle,
};
use tokio::signal::unix::{Signal, SignalKind, signal};

use super::{configuration::HostConfig, destination::DemoDestination};
use crate::constants::EXAMPLE_NAMESPACE;

pub(crate) struct PersistentHost {
    config: HostConfig,
    writer: BufferedWrites<u64>,
    lifecycle: TokioLifecycle,
    destination: DemoDestination,
    guard: RuntimeGuard,
    terminate: Signal,
    prestop: Signal,
}

impl PersistentHost {
    pub(crate) async fn try_new(config: HostConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // The host owns signal registration before it admits application work.
        let terminate = signal(SignalKind::terminate())?;
        let prestop = signal(SignalKind::user_defined1())?;
        let destination = DemoDestination::try_new(config.destination_delay)?;
        let writer =
            BufferedWrites::builder(EXAMPLE_NAMESPACE, destination.sink.clone()).build()?;
        let lifecycle = Lifecycle::tokio();
        let guard = writer.start(lifecycle.clone()).await?;
        writer.add_write_item(config.value).await?;
        // A real HTTP host calls this after its response body completes.
        lifecycle.notify_response_completed();
        Ok(Self {
            config,
            writer,
            lifecycle,
            destination,
            guard,
            terminate,
            prestop,
        })
    }

    pub(crate) async fn serve_signals(mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "{}",
            serde_json::json!({"event":"ready", "driver_active":self.guard.is_active(),
            "maximum":self.destination.maximum.load(Ordering::SeqCst)})
        );
        std::io::stdout().flush()?;
        tokio::select! {
            Some(()) = self.terminate.recv() => {},
            Some(()) = self.prestop.recv() => {},
        }
        let deadline = Deadline::after(self.config.shutdown_grace);
        self.lifecycle.notify_shutdown(deadline);
        let draining = self.writer.shutdown(deadline);
        tokio::pin!(draining);
        loop {
            tokio::select! {
                report = &mut draining => return self.finish_drain(report),
                Some(()) = self.terminate.recv() => self.lifecycle.notify_shutdown(deadline),
                Some(()) = self.prestop.recv() => self.lifecycle.notify_shutdown(deadline),
            }
        }
    }

    fn finish_drain(&self, report: DrainReport) -> Result<(), Box<dyn std::error::Error>> {
        println!(
            "{}",
            serde_json::json!({"event":"drained", "clean":report.is_clean(),
            "unresolved_items":report.unresolved_items, "state_unknown":report.state_unknown,
            "elapsed_ms":report.elapsed.as_millis(), "maximum":self.destination.maximum.load(Ordering::SeqCst)})
        );
        std::io::stdout().flush()?;
        if report.is_clean() {
            Ok(())
        } else {
            Err("buffer drain is incomplete".into())
        }
    }
}
