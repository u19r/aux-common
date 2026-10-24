use serde::{Serialize, de::DeserializeOwned};

use super::{
    extensions_api::ExtensionsApi, protocol::LambdaExtensionEvent, server::LambdaExtensionServer,
};
use crate::{DrainReport, LifecycleError, WriteEvent};

impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> LambdaExtensionServer<T> {
    /// Run classic Lambda Extensions API and IPC together. No worker is
    /// detached. After SHUTDOWN drains, the process owner must exit
    /// promptly with this report.
    pub async fn run(
        &self,
        runtime_api: &str,
        extension_name: &str,
    ) -> Result<DrainReport, LifecycleError> {
        let _service = self.claim_service()?;
        let api = ExtensionsApi::try_new(runtime_api, extension_name)?;
        let events = self.run_events(api);
        tokio::pin!(events);
        tokio::select! {
            report = &mut events => report,
            result = self.serve_owned() => { result?; events.await },
        }
    }

    async fn run_events(&self, api: ExtensionsApi) -> Result<DrainReport, LifecycleError> {
        let api = api.register().await?;
        loop {
            let event = api.next().await?;
            let deadline = event.event.deadline()?;
            match event.event {
                LambdaExtensionEvent::Invoke { request_id, .. } => {
                    self.begin_invocation(&event.identifier, &request_id, deadline)?;
                    match self.await_invoke_completion(&event.identifier).await {
                        Ok(_) => {}
                        Err(error @ LifecycleError::DeadlineExceeded) => self
                            .observer
                            .observe(WriteEvent::LifecycleSourceFailed { error }),
                        Err(error) => return Err(error),
                    }
                }
                LambdaExtensionEvent::Shutdown { .. } => return self.shutdown(deadline).await,
            }
        }
    }
}
