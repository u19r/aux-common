mod execution;
mod guest_memory;
mod imports;
mod limits;
mod module;
mod state;
mod streams;
mod ticker;
pub use execution::JsExecutor;

#[cfg(test)]
mod execution_tests;
#[cfg(test)]
mod imports_tests;
#[cfg(test)]
mod module_tests;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod ticker_tests;
