use std::{
    alloc::{GlobalAlloc, Layout, System},
    fs::OpenOptions,
    io::Write,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use serde::Serialize;

use crate::constants::{REPORT_EVENT, REPORT_PATH_ENV, REPORT_SCHEMA_VERSION};

#[derive(Debug, Clone, Serialize)]
pub struct AllocationReport<'a> {
    pub schema_version: u32,
    pub event: &'static str,
    pub module_path: &'a str,
    pub test_name: &'a str,
    pub file: &'a str,
    pub line: u32,
    pub label: Option<&'a str>,
    pub allocation_count: u64,
    pub allocated_bytes: u64,
}

static RECORDING_ENABLED: AtomicBool = AtomicBool::new(false);
static ALLOCATION_COUNT: AtomicU64 = AtomicU64::new(0);
static ALLOCATION_BYTES: AtomicU64 = AtomicU64::new(0);
static MEASUREMENT_LOCK: Mutex<()> = Mutex::new(());

pub struct AllocationGuard<'a> {
    module_path: &'a str,
    test_name: &'a str,
    file: &'a str,
    line: u32,
    label: Option<&'a str>,
    finished: bool,
    _measurement_lock: MutexGuard<'static, ()>,
}

impl<'a> AllocationGuard<'a> {
    #[must_use]
    pub fn start(
        module_path: &'a str,
        test_name: &'a str,
        file: &'a str,
        line: u32,
        label: Option<&'a str>,
    ) -> Self {
        let measurement_lock = lock_measurement();
        RECORDING_ENABLED.store(false, Ordering::SeqCst);
        ALLOCATION_COUNT.store(0, Ordering::Relaxed);
        ALLOCATION_BYTES.store(0, Ordering::Relaxed);
        RECORDING_ENABLED.store(true, Ordering::SeqCst);

        Self {
            module_path,
            test_name,
            file,
            line,
            label,
            finished: false,
            _measurement_lock: measurement_lock,
        }
    }

    #[must_use]
    pub fn finish(mut self) -> AllocationReport<'a> {
        RECORDING_ENABLED.store(false, Ordering::SeqCst);
        self.finished = true;

        AllocationReport {
            schema_version: REPORT_SCHEMA_VERSION,
            event: REPORT_EVENT,
            module_path: self.module_path,
            test_name: self.test_name,
            file: self.file,
            line: self.line,
            label: self.label,
            allocation_count: ALLOCATION_COUNT.load(Ordering::Relaxed),
            allocated_bytes: ALLOCATION_BYTES.load(Ordering::Relaxed),
        }
    }
}

impl Drop for AllocationGuard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            RECORDING_ENABLED.store(false, Ordering::SeqCst);
        }
    }
}

#[must_use]
pub fn report_json(report: &AllocationReport<'_>) -> Option<String> {
    serde_json::to_string(report).ok()
}

pub fn emit_report(report: &AllocationReport<'_>) {
    let Some(json) = report_json(report) else {
        return;
    };

    println!("{json}");
    append_json_line_if_configured(&json);
}

fn append_json_line_if_configured(json: &str) {
    let Ok(path) = std::env::var(REPORT_PATH_ENV) else {
        return;
    };

    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };

    let _ = file.write_all(json.as_bytes());
    let _ = file.write_all(b"\n");
}

fn lock_measurement() -> MutexGuard<'static, ()> {
    match MEASUREMENT_LOCK.lock() {
        Ok(lock) => lock,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[inline]
fn record_allocation_if_enabled(ptr: *mut u8, size: usize) {
    if ptr.is_null() || !RECORDING_ENABLED.load(Ordering::Relaxed) {
        return;
    }

    saturating_add(&ALLOCATION_COUNT, 1);
    let size_u64 = u64::try_from(size).unwrap_or(u64::MAX);
    saturating_add(&ALLOCATION_BYTES, size_u64);
}

fn saturating_add(counter: &AtomicU64, delta: u64) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(delta);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

struct CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

// SAFETY: This implementation forwards all allocation operations to `System`.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Delegates to the system allocator with the same layout.
        let ptr = unsafe { System.alloc(layout) };
        record_allocation_if_enabled(ptr, layout.size());
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Delegates to the system allocator with the same layout.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        record_allocation_if_enabled(ptr, layout.size());
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: Delegates to the system allocator with the same pointer and layout.
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: Delegates to the system allocator with the same pointer and layout.
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        record_allocation_if_enabled(new_ptr, new_size);
        new_ptr
    }
}
