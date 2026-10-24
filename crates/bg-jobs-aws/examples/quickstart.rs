use bg_jobs_aws::{CredentialSource, SigV4Authorizer};
use bg_jobs_http::{ApprovedEndpoint, HttpExecutor, HttpPolicy, HttpPolicyId};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy_id = HttpPolicyId::try_new("signed-api")?;
    let authorizer =
        SigV4Authorizer::try_new("eu-west-1", "execute-api", CredentialSource::DefaultChain)?;
    let policy = HttpPolicy::builder(policy_id)
        .endpoint(ApprovedEndpoint::exact("api.example.com")?)
        .authorizer(authorizer)
        .try_build()?;
    let _executor = HttpExecutor::try_new([policy])?;
    Ok(())
}
