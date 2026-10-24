use super::{
    driver::ScheduleWakeDriver,
    types::{ResultClass, ScheduleOutcome},
};

#[test]
fn given_initial_schedule_when_current_wake_is_set_then_projection_records_wake_and_stale_replay() {
    let mut driver = ScheduleWakeDriver::try_default().expect("connector initializes");

    driver
        .wake(0, 0, false, false)
        .expect("current wake is accepted");
    assert!(driver.projection.state.wake_pending);
    assert_eq!(driver.projection.state.wake_at, 5);
    assert_eq!(driver.projection.state.wake_revision, 0);
    assert_eq!(driver.projection.state.wake_token, 1);
    assert_eq!(
        driver.projection.state.last_outcome,
        ScheduleOutcome::WakeSet
    );
    assert_eq!(
        driver.projection.last_transition.class,
        ResultClass::AppliedClass
    );

    driver
        .wake(0, 0, false, false)
        .expect("stale wake is classified");
    assert!(driver.projection.state.wake_pending);
    assert_eq!(driver.projection.state.wake_token, 1);
    assert_eq!(
        driver.projection.state.last_outcome,
        ScheduleOutcome::WakeStale
    );
    assert_eq!(
        driver.projection.last_transition.class,
        ResultClass::RejectedClass
    );
}

#[test]
fn given_current_policy_when_overlap_changes_then_projection_records_pause_change() {
    let mut driver = ScheduleWakeDriver::try_default().expect("connector initializes");

    driver
        .policy(true, false, true)
        .expect("policy is applied through the connector");
    assert!(driver.projection.state.enabled);
    assert!(!driver.projection.state.paused);
    assert!(driver.projection.state.overlap);
    assert_eq!(driver.projection.state.revision, 0);
    assert_eq!(
        driver.projection.state.last_outcome,
        ScheduleOutcome::PauseChanged
    );
    assert_eq!(
        driver.projection.last_transition.class,
        ResultClass::AppliedClass
    );
}
