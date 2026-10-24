use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use buffered_writes::{BufferedWrites, FlushThresholds, LambdaExtensionServer};

use super::{configuration::ExtensionConfig, destination::DemoDestination};
use crate::constants::DEMO_NAMESPACE;

pub(crate) struct ExtensionHost {
    server: LambdaExtensionServer<u64>,
    maximum: Arc<AtomicU64>,
    runtime_api: String,
}

impl ExtensionHost {
    pub(crate) async fn try_new(
        config: ExtensionConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let destination = DemoDestination::try_new(config.destination_delay)?;
        let writer = BufferedWrites::builder(DEMO_NAMESPACE, destination.sink)
            .flush_policy(FlushThresholds::default().max_age(config.flush_age))
            .build()?;
        let server = LambdaExtensionServer::bind(writer, config.ipc).await?;
        Ok(Self {
            server,
            maximum: destination.maximum,
            runtime_api: config.runtime_api,
        })
    }

    pub(crate) async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        let name = executable_name()?;
        println!(
            "{}",
            serde_json::json!({"event":"ready", "process_id":std::process::id(), "ipc_address":self.server.local_addr()?.to_string()})
        );
        let report = self.server.run(&self.runtime_api, &name).await?;
        println!(
            "{}",
            serde_json::json!({"event":"drained", "clean":report.is_clean(), "unresolved_items":report.unresolved_items, "quarantined_items":report.quarantined_items, "state_unknown":report.state_unknown, "items_settled":report.items_settled, "maximum":self.maximum.load(Ordering::SeqCst)})
        );
        if !report.is_clean() {
            return Err("buffer drain is incomplete".into());
        }
        Ok(())
    }
}

fn executable_name() -> Result<String, Box<dyn std::error::Error>> {
    std::env::current_exe()?
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| "invalid extension filename".into())
}
