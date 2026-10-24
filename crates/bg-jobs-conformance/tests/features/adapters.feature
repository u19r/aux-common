@F005
Feature: High-level adapters and backend readiness

  @F005_S001
  Scenario: HTTP defaults classify outcomes durably
    Given a registered HTTPS job uses the shared executor with transport retries disabled
    When it receives success throttling permanent rejection or transport failure
    Then each response maps to the documented per-job terminal or retry outcome

  @F005_S002
  Scenario: HTTP retries propagate one idempotency identity
    Given an HTTP job is automatically retried
    When each request is built
    Then the stable execution ID is sent in the registered idempotency header
    And URLs bodies headers and raw errors are absent from telemetry

  @F005_S003
  Scenario: SigV4 credentials remain execution-time secrets
    Given a job selects a trusted AWS authorizer reference
    When the approved HTTPS request executes
    Then existing credential providers resolve and sign it at execution time
    And no credential is persisted in payload state or events

  @F005_S004
  Scenario: Generic conformance leaves distributed authority to the backend
    Given a candidate backend claims Distributed support
    When the reusable basic and fault suite runs
    Then generic checked-write and stale-token semantics pass

  @F005_S005
  Scenario: Weak storage cannot claim multi-node safety
    Given storage has get put and range but no atomic checked multi-key commit
    When a distributed job system is constructed
    Then construction or conformance fails explicitly

  @F005_S006
  Scenario: WASM-neutral contracts compile
    Given bg-jobs and bg-jobs-conformance use the reference fake adapter
    When built for wasm32-unknown-unknown
    Then they require no Tokio reqwest native TLS AWS SDK or database backend

  @F005_S007
  Scenario: Tiny and large profiles remain explicitly bounded
    Given one-core and multi-driver budgets
    When identical work mixes are measured
    Then both obey concurrency payload transaction deadline and retained-memory caps

  @F005_S008
  Scenario: Native bulk reads remain preserved
    Given a wrapped native bulk-read store
    When the public conformance workflow runs
    Then bulk reads stay native
