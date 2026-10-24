mod schema_generator;

pub(crate) use schema_generator::ensure_unique_resource_entity_names;
pub use schema_generator::{
    generate_base_schema, generate_schema, generate_schema_for_resource, to_pascal_case,
};

#[cfg(test)]
mod schema_generator_tests;
