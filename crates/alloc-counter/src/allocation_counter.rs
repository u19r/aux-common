#[cfg(not(feature = "opt-loop-profiling"))]
use std::alloc::System;
use std::{
    alloc::{GlobalAlloc, Layout},
    cell::Cell,
    fs::OpenOptions,
    io::Write,
    marker::PhantomData,
    rc::Rc,
};

#[cfg(feature = "opt-loop-profiling")]
use opt_loop_probe::ProbeAllocator;
use serde::Serialize;

use crate::constants::{REPORT_EVENT, REPORT_PATH_ENV, REPORT_SCHEMA_VERSION};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocationReportError {
    Serialize,
    OpenReportFile,
    WriteReportFile,
}

impl std::fmt::Display for AllocationReportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::Serialize => "allocation report serialization failed",
            Self::OpenReportFile => "allocation report file could not be opened",
            Self::WriteReportFile => "allocation report file could not be written",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AllocationReportError {}

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

std::thread_local! {
    static RECORDING_COUNTS: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
}

pub struct AllocationGuard<'a> {
    module_path: &'a str,
    test_name: &'a str,
    file: &'a str,
    line: u32,
    label: Option<&'a str>,
    finished: bool,
    _thread_bound: PhantomData<Rc<()>>,
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
        start_recording();

        Self {
            module_path,
            test_name,
            file,
            line,
            label,
            finished: false,
            _thread_bound: PhantomData,
        }
    }

    #[must_use]
    pub fn finish(mut self) -> AllocationReport<'a> {
        let (allocation_count, allocated_bytes) = stop_recording();
        self.finished = true;

        AllocationReport {
            schema_version: REPORT_SCHEMA_VERSION,
            event: REPORT_EVENT,
            module_path: self.module_path,
            test_name: self.test_name,
            file: self.file,
            line: self.line,
            label: self.label,
            allocation_count,
            allocated_bytes,
        }
    }
}

impl Drop for AllocationGuard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            stop_recording();
        }
    }
}

#[must_use = "handle allocation report serialization errors"]
pub fn report_json(report: &AllocationReport<'_>) -> Result<String, AllocationReportError> {
    serde_json::to_string(report).map_err(|_| AllocationReportError::Serialize)
}

#[must_use = "handle allocation report emission errors"]
pub fn emit_report(report: &AllocationReport<'_>) -> Result<(), AllocationReportError> {
    let json = report_json(report)?;
    append_json_line_if_configured(&json)
}

fn append_json_line_if_configured(json: &str) -> Result<(), AllocationReportError> {
    let Ok(path) = std::env::var(REPORT_PATH_ENV) else {
        return Ok(());
    };

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|_| AllocationReportError::OpenReportFile)?;

    file.write_all(json.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|_| AllocationReportError::WriteReportFile)
}

fn start_recording() {
    RECORDING_COUNTS.with(|counts| {
        assert!(
            counts.get().is_none(),
            "allocation measurements cannot be nested on one thread"
        );
        counts.set(Some((0, 0)));
    });
}

fn stop_recording() -> (u64, u64) {
    RECORDING_COUNTS.with(|counts| counts.replace(None).unwrap_or_default())
}

#[inline]
fn record_allocation_if_enabled(ptr: *mut u8, size: usize) {
    if ptr.is_null() {
        return;
    }

    let _ = RECORDING_COUNTS.try_with(|counts| {
        let Some((allocation_count, allocated_bytes)) = counts.get() else {
            return;
        };
        let size_u64 = u64::try_from(size).unwrap_or(u64::MAX);
        counts.set(Some((
            allocation_count.saturating_add(1),
            allocated_bytes.saturating_add(size_u64),
        )));
    });
}

struct CountingAllocator;

#[cfg(feature = "opt-loop-profiling")]
static BACKING_ALLOCATOR: ProbeAllocator = ProbeAllocator::new();
#[cfg(not(feature = "opt-loop-profiling"))]
static BACKING_ALLOCATOR: System = System;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

// SAFETY: This implementation forwards every operation to the selected backing
// allocator.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Delegates to the backing allocator with the same layout.
        let ptr = unsafe { BACKING_ALLOCATOR.alloc(layout) };
        record_allocation_if_enabled(ptr, layout.size());
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Delegates to the backing allocator with the same layout.
        let ptr = unsafe { BACKING_ALLOCATOR.alloc_zeroed(layout) };
        record_allocation_if_enabled(ptr, layout.size());
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: Delegates to the backing allocator with the same pointer and
        // layout.
        unsafe { BACKING_ALLOCATOR.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: Delegates to the backing allocator with the same pointer,
        // layout, and size.
        let new_ptr = unsafe { BACKING_ALLOCATOR.realloc(ptr, layout, new_size) };
        record_allocation_if_enabled(new_ptr, new_size);
        new_ptr
    }
}
