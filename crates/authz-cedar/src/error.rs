use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CedarError {
    #[error("Schema generation failed: {message}")]
    SchemaGeneration { message: String },

    #[error("Policy generation failed: {message}")]
    PolicyGeneration { message: String },

    #[error("Template generation failed: {message}")]
    TemplateGeneration { message: String },

    #[error("Bundle compilation failed: {message}")]
    BundleCompilation { message: String },

    #[error("Evaluation failed: {message}")]
    Evaluation { message: String },

    #[error("Not implemented: {topic}")]
    NotImplemented { topic: &'static str },
}

impl CedarError {
    pub fn schema_generation(message: impl Into<String>) -> Self {
        Self::SchemaGeneration {
            message: message.into(),
        }
    }

    pub fn policy_generation(message: impl Into<String>) -> Self {
        Self::PolicyGeneration {
            message: message.into(),
        }
    }

    pub fn template_generation(message: impl Into<String>) -> Self {
        Self::TemplateGeneration {
            message: message.into(),
        }
    }

    pub fn bundle_compilation(message: impl Into<String>) -> Self {
        Self::BundleCompilation {
            message: message.into(),
        }
    }

    pub fn evaluation(message: impl Into<String>) -> Self {
        Self::Evaluation {
            message: message.into(),
        }
    }

    pub fn not_implemented(topic: &'static str) -> Self {
        Self::NotImplemented { topic }
    }
}
