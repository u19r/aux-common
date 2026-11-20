# aws-sigv4-signing

Reusable AWS Signature Version 4 helpers.

Signs HTTP requests with static credentials or a small default credential chain:
environment variables, AWS CLI profile export, ECS task metadata, then EC2 IMDS. Only an
unconfigured source yields to the next; a configured source's failure is returned. Resolved
default-chain credentials are cached with the workspace `lru-ttl-cache` crate until their refresh
deadline.

The crate is intentionally narrow:

- build signed header maps and presigned URIs; presigned URIs always sign `UNSIGNED-PAYLOAD`,
  and callers that send signed headers themselves must disable redirects;
- expose a lightweight signed HTTP client wrapper;
- keep credential-provider constants and error messages co-located for review;
- avoid leaking credentials or tokens through logs or error text.
