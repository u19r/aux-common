mod constants;
mod runtime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    runtime::DemoRuntime::from_env()?.run().await
}
