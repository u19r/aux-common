mod parser;

pub use parser::{ClientData, parse_client_data};
pub(crate) use parser::{is_valid_origin, normalize_origin};

#[cfg(test)]
mod parser_tests;
