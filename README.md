# aux-common

Shared Rust utility crates.

## Public Authz Crates

`aux-common` also owns public authorization crates shared by AuxFn services and the sidecar:

- `authz-types`: storage-free authorization request, response, configuration, token, JWT context,
  and step-up domain types.
- `authz-cedar`: deterministic Cedar policy bundle generation, parsing, and evaluation helpers.

These crates are intentionally public so customers can inspect local authorization evaluation
behavior. Private AuxFn storage schemas, route handlers, service-token validation, API-key
validation, audit writes, bootstrap defaults, and application-specific policy data stay in the
calling repositories.
