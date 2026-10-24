mod constants;
mod policy_generator;

pub(crate) use policy_generator::{
    PolicyDocument, StaticPolicyEntry, TemplateGroup, TemplateLinkEntry,
    generate_policy_document_for_resource,
};
pub use policy_generator::{generate_static_policies, generate_static_policies_for_resource};

#[cfg(test)]
mod policy_generator_tests;
