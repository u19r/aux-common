pub const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub(crate) const NS_XML: &str = "http://www.w3.org/XML/1998/namespace";
pub(crate) const NS_XMLNS: &str = "http://www.w3.org/2000/xmlns/";
pub(crate) const NS_XINCLUDE: &str = "http://www.w3.org/2001/XInclude";
pub(crate) const NS_XMLENC: &str = "http://www.w3.org/2001/04/xmlenc#";
pub const SAML_PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

pub(crate) const EXCLUSIVE_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub(crate) const ENVELOPED_SIGNATURE: &str =
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub(crate) const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub(crate) const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub(crate) const MAX_PUBLIC_KEY_BYTES: usize = 8 * 1024;
pub(crate) const MAX_SIGNATURE_BYTES: usize = 8 * 1024;
