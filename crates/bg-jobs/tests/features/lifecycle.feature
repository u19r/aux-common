@F001
Feature: Durable job lifecycle

  @F001_S001
  Scenario: A due job completes and returns bounded details
    Given a registered scoped job with an opaque primary key
    When it is enqueued and driven
    Then it executes once in the healthy case
    And its durable job and payload state are deleted
    And bounded completion details are returned after commit

  @F001_S002
  Scenario: Duplicate enqueue reconciles by stable job ID
    Given an enqueue commit acknowledgement is lost
    When the caller retries the identical job ID and bytes
    Then it receives AlreadyPresent and the same wake hint
    But different immutable bytes return JobIdConflict

  @F001_S003
  Scenario: Payload bounds are portable
    Given a store whose value limit is smaller than 950 KiB
    When a 950 KiB job is enqueued
    Then bounded chunks commit atomically and execute correctly
    But a payload above 950 KiB fails before storage I/O

  @F001_S004
  Scenario: Future work does not cause empty polling
    Given only a future job exists
    When one drive finds no immediately useful work
    Then it returns the future WakeHint and exits

  @F001_S005
  Scenario: Completion details may be discarded or audited by the caller
    Given the engine returned completion details after deleting the job
    When caller-owned audit persistence fails or is omitted
    Then aux-common does not recreate or retry the completed job
