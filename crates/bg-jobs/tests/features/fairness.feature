@F003
Feature: Fair priority and batch execution

  @F003_S001
  Scenario: A quiet primary scope receives bounded service
    Given one primary scope supplies ninety percent of due cost
    And another primary scope becomes due
    When processors are available
    Then the quiet scope starts within the configured scheduler error bound

  @F003_S002
  Scenario: Secondary scopes cannot multiply a primary share
    Given many secondary keys exist under one primary key
    When they compete with another primary key
    Then they subdivide only their primary service and permit budget

  @F003_S003
  Scenario: Low-volume mode is explicit and registration-bound
    Given a high-volume definition requires scoped fairness
    When enqueue selects LowVolume
    Then validation fails before storage I/O
    But a registered low-volume maintenance job uses the capped aggregate class

  @F003_S004
  Scenario: Priority weights do not starve bulk work
    Given Critical Default and Bulk remain backlogged
    When enough dispatch cost is observed
    Then service approximates 8 to 4 to 1 and every lane progresses

  @F003_S005
  Scenario: One blocked candidate does not block its queue
    Given the oldest job is leased capacity-blocked or corrupt
    When independent eligible work exists
    Then bounded discovery skips the blocked item and claims independent work

  @F003_S006
  Scenario: Batch outcomes remain per item
    Given a compatible bounded batch has successes retryable failures and one omitted result
    When the handler returns outcomes
    Then successes complete and only unresolved items retry

  @F003_S007
  Scenario: Ordering is local to one group
    Given two ordering groups have due jobs and one group contains a poison head
    When a batch is driven
    Then jobs within each group remain serial while the other group progresses

  @F003_S008
  Scenario: Repeated drives reuse bounded scratch memory
    Given small and maximum-sized jobs run repeatedly
    When drive sessions finish
    Then candidate capacity is reused and pathological retained capacity is shrunk

  @F003_S009
  Scenario: Schedule overlap consumes one primary permit
    Given a schedule has two due overlap-forbidden occurrences in one ordering group
    When the public engine drives with two available permits
    Then overlap-forbidden work claims at most one permit

  @F003_S010
  Scenario: Independent systems preserve durable primary capacity
    Given two independent systems share a distributed store with per-primary capacity
    When claimants overlap and the remaining system drives
    Then the conflict spends no fairness credit and both primaries receive durable capacity
