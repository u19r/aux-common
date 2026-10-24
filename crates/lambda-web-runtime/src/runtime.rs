use super::{LambdaWebEnvironment, LambdaWebRuntimeError, constants::READY_TIMEOUT};

impl LambdaWebEnvironment {
    /// Acknowledge readiness after binding the server's listener.
    pub async fn notify_ready(&self) -> Result<(), LambdaWebRuntimeError> {
        let client = reqwest::Client::builder()
            .timeout(READY_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| LambdaWebRuntimeError::ReadyUnavailable)?;
        let response = client
            .post(self.ready_url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body("{}")
            .send()
            .await
            .map_err(|_| LambdaWebRuntimeError::ReadyUnavailable)?;
        if !response.status().is_success() {
            return Err(LambdaWebRuntimeError::ReadyRejected(
                response.status().as_u16(),
            ));
        }
        Ok(())
    }
}

impl LambdaWebEnvironment {
    /// Run the server until completion or shutdown. After shutdown, allow a
    /// bounded drain and cancel remaining requests before Lambda terminates.
    /// The caller's shutdown future must initiate graceful server shutdown.
    /// `None` means the drain deadline elapsed and the server was cancelled.
    pub async fn run_until_shutdown<F, S>(&self, server: F, shutdown: S) -> Option<F::Output>
    where
        F: std::future::Future,
        S: std::future::Future<Output = ()>,
    {
        tokio::pin!(server);
        tokio::pin!(shutdown);
        tokio::select! {
            output = &mut server => Some(output),
            () = &mut shutdown => tokio::time::timeout(self.shutdown_grace(), server).await.ok(),
        }
    }
}
