@F002
Feature: Failure and multi-node recovery

  @F002_S001
  Scenario: Two nodes race for one claim
    Given two distributed drivers discover the same due job
    When both commit a claim
    Then only one token and fence become authoritative

  @F002_S002
  Scenario: A stale worker cannot complete reclaimed work
    Given an old lease expires and a successor claims the job
    When the old worker renews checkpoints or completes
    Then every stale mutation is rejected without changing successor state

  @F002_S003
  Scenario: Automatic retries preserve downstream idempotency
    Given a transient or ambiguous effect failure
    When the job retries under Network policy
    Then every attempt receives the same execution ID
    And each attempt receives a unique attempt ID

  @F002_S004
  Scenario: Retry bounds isolate poison work
    Given a handler fails until attempts or maximum age is exhausted
    When other due jobs are present
    Then the failed job becomes dead-lettered
    And unrelated work continues without head-of-line blocking

  @F002_S005
  Scenario: Unknown completion commit is reconciled
    Given the store committed completion but returned Unknown
    When the engine reconciles by job ID token fence and operation ID
    Then it reports one success without invoking the handler again

  @F002_S006
  Scenario: Redrive makes effect intent explicit
    Given a dead-lettered job may already have caused an effect
    When redrive selects reuse or rotation of the execution ID
    Then generation increments and the selected identity is returned for caller auditing

  @F002_S007
  Scenario: Sensitive failure data is unrepresentable in core telemetry
    Given raw errors contain payloads URLs headers identifiers and credentials
    When retry and DLQ events are observed
    Then events and metric labels contain only proven bounded fields

  @F002_S008
  Scenario: A panicking handler becomes a durable retry while peer work continues
    Given a handler panics while a peer is due
    When the public drive handles both
    Then the panic becomes a durable retry and the peer completes

  @F002_S009
  Scenario: Persisted identity tampering is isolated
    Given a persisted job record has a foreign identity and an unrelated peer is due
    When the public drive encounters the tampered record
    Then the tampered record is isolated and the peer completes

  @F002_S010
  Scenario: Terminal cancellation consumes authority
    Given a due job is claimed before cancellation acknowledgement
    When the public cancellation acknowledgement commits
    Then no claimant can reuse the terminal cancellation authority
