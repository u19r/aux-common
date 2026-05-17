# aws-sigv4-signing

Internal AWS Signature Version 4 helpers for aux-storage clients and service integrations.

This crate signs HTTP requests with static credentials or a small default credential chain:
environment variables, AWS CLI profile export, ECS task metadata, then EC2 IMDS. Resolved
default-chain credentials are cached with the workspace `lru-ttl-cache` crate until their refresh
deadline.

The crate is intentionally narrow:

- build signed header maps and presigned URIs;
- expose a lightweight signed HTTP client wrapper;
- keep credential-provider constants and error messages co-located for review;
- avoid leaking credentials or tokens through logs or error text.
