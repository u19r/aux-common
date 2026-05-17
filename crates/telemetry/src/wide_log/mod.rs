mod field_security;
mod otel_log_entry;
mod sink;
mod span_state;
mod trace_rule;
mod wide_log_impl;

#[cfg(test)]
pub(crate) use field_security::{SpanFields, has_sensitive_suffix};
pub use sink::WideLogInitError;
pub use wide_log_impl::WideLogLayer;

#[cfg(test)]
mod wide_log_impl_tests;
