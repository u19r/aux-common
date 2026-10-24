use super::constants::{SAML_BINDING_HTTP_POST, SAML_BINDING_HTTP_REDIRECT, SAML_METADATA_NS};
use crate::{SamlError, bindings::validate_redirect_destination};

/// The request binding a caller will use at the identity provider's SSO
/// endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataSsoBinding {
    HttpPost,
    HttpRedirect,
}

impl MetadataSsoBinding {
    pub(super) fn parse_sso_url(
        self,
        idp: &xml_security::UnverifiedElement,
    ) -> Result<String, SamlError> {
        let (binding_uri, binding_name) = match self {
            Self::HttpPost => (SAML_BINDING_HTTP_POST, "HTTP-POST"),
            Self::HttpRedirect => (SAML_BINDING_HTTP_REDIRECT, "HTTP-Redirect"),
        };
        let mut endpoints = idp.child_elements().filter(|child| {
            child.name() == "SingleSignOnService"
                && child.namespace() == Some(SAML_METADATA_NS)
                && child.attr("Binding") == Some(binding_uri)
        });
        let endpoint = endpoints.next().ok_or_else(|| {
            SamlError::InvalidInput(format!("{binding_name} SingleSignOnService is required"))
        })?;
        if endpoints.next().is_some() {
            return Err(SamlError::Unsupported(format!(
                "multiple {binding_name} SingleSignOnService values are not supported"
            )));
        }
        let url = endpoint.attr("Location").ok_or_else(|| {
            SamlError::InvalidInput("SingleSignOnService Location is required".to_string())
        })?;
        validate_redirect_destination(url)?;
        Ok(url.to_string())
    }
}
