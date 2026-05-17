use std::time::SystemTime;

pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

#[derive(Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}
