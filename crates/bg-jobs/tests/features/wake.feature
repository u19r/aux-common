@F004
Feature: Trigger-neutral schedules and wakes

  @F004_S001
  Scenario: Portable cron is deterministic
    Given a valid five-field UTC expression
    When two nodes materialise the same occurrence
    Then the cron crate calculates one intended time and one deterministic job commits

  @F004_S002
  Scenario: Non-portable cron is rejected
    Given seconds years aliases local time or provider extensions
    When schedule registration validates the expression
    Then it fails before durable state changes

  @F004_S003
  Scenario: Misfire policies are bounded
    Given several occurrences were missed while offline
    When Skip FireOnce or CatchUp is selected
    Then each policy emits its defined bounded occurrence count

  @F004_S004
  Scenario: Duplicate and lost external wakes are safe
    Given wake delivery is duplicated or the prompt notification is lost
    When a one-minute safety trigger later drives work
    Then no duplicate claim becomes authoritative and accepted work starts

  @F004_S005
  Scenario: A serverless active pulse drains then exits
    Given a burst exceeds one drive but fits the invocation budget
    When repeated reports return WakeHint Now
    Then the adapter yields and drives again until no work is immediately useful
    And it does not poll the empty store for the rest of the minute

  @F004_S006
  Scenario: Invocation deadlines stop claims before hard timeout
    Given due work exceeds the remaining Lambda or Worker budget
    When stop-claiming time is reached
    Then active outcomes are persisted and remaining work returns WakeHint Now

  @F004_S008
  Scenario: An already-expired monotonic clock prevents new claims
    Given due work is present while the drive clock is already expired
    When the public drive observes the expired clock
    Then it stops before invoking a handler and leaves due work durable

  @F004_S007
  Scenario: Pausing and cancellation do not destroy unrelated work
    Given a schedule queue or job is paused or cancelled
    When drive and resume operations race
    Then checked generations produce one valid state and unrelated work remains runnable
