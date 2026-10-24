//! Fixed generic execution and protocol ceilings; callers may impose smaller
//! limits.
#[cfg(feature = "runtime")]
use std::time::Duration;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_SOURCE_BYTES: usize = 65_536;
pub const MAX_ARGUMENT_BYTES: usize = 262_144;
pub const MAX_RESULT_BYTES: usize = 262_144;
pub const MAX_JOB_BYTES: usize = 1_048_576;
pub const MAX_REPLY_BYTES: usize = MAX_RESULT_BYTES + 128;
pub const MAX_ARGUMENTS: usize = 16;
pub const MAX_BINDINGS: usize = 16;
pub const MAX_IDENTIFIER_BYTES: usize = 128;
#[cfg(feature = "runtime")]
pub(crate) const MAX_MEMORY_BYTES: usize = 16 * 1024 * 1024;
#[cfg(feature = "runtime")]
pub(crate) const MAX_MEMORY_PAGES: u64 = 256;
#[cfg(feature = "runtime")]
pub(crate) const MAX_TABLE_ELEMENTS: usize = 4096;
#[cfg(feature = "runtime")]
pub(crate) const MAX_WASM_STACK_BYTES: usize = 512 * 1024;
#[cfg(feature = "runtime")]
pub(crate) const JOB_FUEL: u64 = 1_000_000_000;
#[cfg(feature = "runtime")]
pub(crate) const JOB_DEADLINE: Duration = Duration::from_millis(50);
#[cfg(feature = "runtime")]
pub(crate) const TICK_INTERVAL: Duration = Duration::from_millis(1);
#[cfg(feature = "runtime")]
pub(crate) const MAX_IOVECS: usize = 16;
#[cfg(feature = "runtime")]
pub(crate) const MAX_RANDOM_BYTES: usize = 256;
#[cfg(feature = "runtime")]
pub(crate) const WASI_MODULE: &str = "wasi_snapshot_preview1";
#[cfg(feature = "runtime")]
pub(crate) const WASI_BADF: i32 = 8;
#[cfg(feature = "runtime")]
pub(crate) const WASI_SPIPE: i32 = 70;

pub(crate) const RESERVED_IDENTIFIERS: &[&str] = &[
    "await",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "implements",
    "import",
    "in",
    "instanceof",
    "interface",
    "let",
    "new",
    "null",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "static",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
    "yield",
];
