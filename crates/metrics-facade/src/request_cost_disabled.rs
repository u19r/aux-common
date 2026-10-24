#[derive(Debug, Default)]
pub struct DatabaseCallGuard;

#[must_use]
pub fn begin_database_call(_operation: &str) -> DatabaseCallGuard {
    DatabaseCallGuard
}
