use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use super::deterministic::TestProfile;
use crate::model::WakeScheduler;

struct CountingWake(Arc<AtomicUsize>);

impl Wake for CountingWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn given_a_pending_sleep_when_virtual_time_advances_then_only_due_sleepers_wake() {
    let profile = TestProfile::new();
    let mut first = profile
        .sleep(Duration::from_nanos(10))
        .expect("first sleep");
    let mut second = profile
        .sleep(Duration::from_nanos(20))
        .expect("second sleep");
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountingWake(Arc::clone(&wakes))));
    let mut context = Context::from_waker(&waker);

    assert!(matches!(first.as_mut().poll(&mut context), Poll::Pending));
    assert!(matches!(second.as_mut().poll(&mut context), Poll::Pending));
    profile.advance(Duration::from_nanos(10));
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    assert!(matches!(first.as_mut().poll(&mut context), Poll::Ready(())));
    assert!(matches!(second.as_mut().poll(&mut context), Poll::Pending));
    profile.advance(Duration::from_nanos(10));
    assert!(matches!(
        second.as_mut().poll(&mut context),
        Poll::Ready(())
    ));
}
