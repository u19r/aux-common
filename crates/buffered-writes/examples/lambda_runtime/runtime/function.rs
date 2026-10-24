use buffered_writes::{LambdaExtensionClient, LambdaIpcConfig};

use super::{invocation::InvocationOutcome, protocol::RuntimeApi};
use crate::constants::DEFAULT_IPC_ADDRESS;

pub(crate) struct DemoRuntime {
    api: RuntimeApi,
    client: LambdaExtensionClient<u64>,
}

impl DemoRuntime {
    pub(crate) fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let endpoint =
            std::env::var("AWS_LAMBDA_RUNTIME_API").map_err(|_| "missing Runtime API endpoint")?;
        let address = std::env::var("BUFFERED_WRITES_IPC_ADDR")
            .unwrap_or_else(|_| DEFAULT_IPC_ADDRESS.to_owned())
            .parse()
            .map_err(|_| "invalid IPC address")?;
        let token = std::env::var("BUFFERED_WRITES_IPC_TOKEN")
            .map_err(|_| "missing IPC capability token")?;
        Ok(Self {
            api: RuntimeApi::try_new(&endpoint)?,
            client: LambdaExtensionClient::new(LambdaIpcConfig::try_new(address, token)?),
        })
    }

    pub(crate) async fn run(mut self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            let invocation = self.api.next().await?;
            let attempt_id = invocation.attempt_id.to_str()?;
            let writes = self
                .client
                .begin_invocation(&invocation.request_id, attempt_id)
                .await
                .ok();
            let outcome = match &writes {
                Some(writes) => invocation.admit(writes).await,
                None => InvocationOutcome::Failure,
            };
            let kind = self.api.complete(&invocation, &outcome).await?;
            println!(
                "{}",
                serde_json::json!({"event":format!("{kind}_acknowledged")})
            );
            if let Some(writes) = writes.filter(|_| outcome.should_mark_complete()) {
                let report = writes.after_response().await?;
                println!(
                    "{}",
                    serde_json::json!({"event":"marker_acknowledged", "items_settled":report.items_settled})
                );
            }
            if outcome.should_exit() {
                return Ok(());
            }
        }
    }
}
