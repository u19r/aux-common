use bg_jobs_http::{
    ApprovedEndpoint, HttpExecutor, HttpJob, HttpPolicy, HttpPolicyId, HttpRequest,
    HttpRequestInput,
};
use bytes::Bytes;
use http::{HeaderMap, Method};
use http_request::Url;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy_id = HttpPolicyId::try_new("partner-webhook")?;
    let policy = HttpPolicy::builder(policy_id.clone())
        .endpoint(ApprovedEndpoint::exact("api.example.com")?)
        .try_build()?;
    let request = HttpRequest::try_new(HttpRequestInput {
        method: Method::POST,
        url: Url::parse("https://api.example.com/jobs")?,
        headers: HeaderMap::new(),
        body: Bytes::from_static(br#"{"ok":true}"#),
    })?;
    let job = HttpJob::new(policy_id, request);
    let executor = HttpExecutor::try_new([policy])?;

    let _ = (job, executor);
    Ok(())
}
