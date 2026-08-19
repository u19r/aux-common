use std::{
    collections::{HashMap, HashSet},
    fmt,
    io::Cursor,
};

use xml::{
    common::XmlVersion,
    reader::{EventReader, ParserConfig, XmlEvent},
};

use crate::XmlSecurityError;

pub const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const NS_XML: &str = "http://www.w3.org/XML/1998/namespace";
const NS_XMLNS: &str = "http://www.w3.org/2000/xmlns/";
pub const SAML_PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmlLimits {
    max_bytes: usize,
    max_depth: usize,
    max_elements: usize,
    max_attributes_per_element: usize,
    max_namespace_bindings_per_element: usize,
    max_namespace_uri_bytes: usize,
    max_namespace_declaration_bytes: usize,
    max_namespace_context_bytes: usize,
}

impl Default for XmlLimits {
    fn default() -> Self {
        Self {
            max_bytes: 512 * 1024,
            max_depth: 64,
            max_elements: 8_192,
            max_attributes_per_element: 128,
            max_namespace_bindings_per_element: 64,
            max_namespace_uri_bytes: 1_024,
            max_namespace_declaration_bytes: 16 * 1024,
            max_namespace_context_bytes: 4 * 1024 * 1024,
        }
    }
}

impl XmlLimits {
    pub fn try_new(max_bytes: usize, max_depth: usize) -> Result<Self, XmlSecurityError> {
        let defaults = Self::default();
        Self {
            max_bytes,
            max_depth,
            max_elements: defaults.max_elements,
            max_attributes_per_element: defaults.max_attributes_per_element,
            max_namespace_bindings_per_element: defaults.max_namespace_bindings_per_element,
            max_namespace_uri_bytes: defaults.max_namespace_uri_bytes,
            max_namespace_declaration_bytes: defaults.max_namespace_declaration_bytes,
            max_namespace_context_bytes: defaults.max_namespace_context_bytes,
        }
        .validate()
    }

    pub fn try_with_cardinality(
        self,
        max_elements: usize,
        max_attributes_per_element: usize,
        max_namespace_bindings_per_element: usize,
    ) -> Result<Self, XmlSecurityError> {
        Self {
            max_elements,
            max_attributes_per_element,
            max_namespace_bindings_per_element,
            ..self
        }
        .validate()
    }

    pub fn try_with_namespace_bytes(
        self,
        max_namespace_uri_bytes: usize,
        max_namespace_declaration_bytes: usize,
        max_namespace_context_bytes: usize,
    ) -> Result<Self, XmlSecurityError> {
        Self {
            max_namespace_uri_bytes,
            max_namespace_declaration_bytes,
            max_namespace_context_bytes,
            ..self
        }
        .validate()
    }

    fn validate(self) -> Result<Self, XmlSecurityError> {
        if self.max_bytes == 0
            || self.max_depth == 0
            || self.max_elements == 0
            || self.max_attributes_per_element == 0
            || self.max_namespace_bindings_per_element == 0
            || self.max_namespace_uri_bytes == 0
            || self.max_namespace_declaration_bytes == 0
            || self.max_namespace_context_bytes == 0
        {
            return Err(XmlSecurityError::Shape {
                message: "XML limits must be non-zero, including cardinality limits".to_string(),
            });
        }
        Ok(self)
    }

    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    #[must_use]
    pub const fn max_depth(self) -> usize {
        self.max_depth
    }

    #[must_use]
    pub const fn max_elements(self) -> usize {
        self.max_elements
    }

    #[must_use]
    pub const fn max_attributes_per_element(self) -> usize {
        self.max_attributes_per_element
    }

    #[must_use]
    pub const fn max_namespace_bindings_per_element(self) -> usize {
        self.max_namespace_bindings_per_element
    }

    #[must_use]
    pub const fn max_namespace_uri_bytes(self) -> usize {
        self.max_namespace_uri_bytes
    }

    #[must_use]
    pub const fn max_namespace_declaration_bytes(self) -> usize {
        self.max_namespace_declaration_bytes
    }

    #[must_use]
    pub const fn max_namespace_context_bytes(self) -> usize {
        self.max_namespace_context_bytes
    }
}

#[derive(Clone)]
pub struct UnverifiedElement {
    name: String,
    namespace: Option<String>,
    prefix: Option<String>,
    attributes: Vec<(String, String)>,
    attribute_namespaces: Vec<Option<String>>,
    children: Vec<Node>,
    ns_uri: Option<String>,
    namespace_context: HashMap<String, String>,
}

impl fmt::Debug for UnverifiedElement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = self
            .attributes
            .iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        formatter
            .debug_struct("UnverifiedElement")
            .field("name", &self.name)
            .field("namespace", &self.namespace)
            .field("prefix", &self.prefix)
            .field("attribute_names", &names)
            .field("attribute_values", &"<redacted>")
            .field("attribute_namespaces", &self.attribute_namespaces)
            .field("children", &self.children)
            .field("ns_uri", &self.ns_uri)
            .field("namespace_context", &self.namespace_context)
            .finish()
    }
}

pub(crate) type Element = UnverifiedElement;

impl UnverifiedElement {
    /// Parse attacker-controlled XML into an explicitly unverified tree.
    ///
    /// Parsing and canonicalisation establish only bounded, well-formed XML;
    /// they do not establish authenticity or integrity. Callers that need
    /// trusted data must use [`crate::VerifiedXmlDocument`] instead.
    pub fn parse_unverified(xml: &str) -> Result<Self, XmlSecurityError> {
        parse_with_limits(xml, XmlLimits::default())
    }

    /// Parse attacker-controlled XML with explicit resource limits.
    pub fn parse_unverified_with_limits(
        xml: &str,
        limits: XmlLimits,
    ) -> Result<Self, XmlSecurityError> {
        parse_with_limits(xml, limits)
    }

    /// Canonicalise an unverified XML tree.
    ///
    /// Canonicalisation is a serialization primitive, not a trust check. The
    /// returned bytes must not be treated as authenticated unless this value
    /// came from a verified signed subtree.
    pub fn canonicalize_unverified(&self) -> Result<Vec<u8>, XmlSecurityError> {
        canonicalize_xml(self)
    }

    pub(crate) fn canonicalize_unverified_with_inclusive_prefixes(
        &self,
        inclusive_prefixes: Option<&[&str]>,
    ) -> Result<Vec<u8>, XmlSecurityError> {
        let prefixes = validate_inclusive_prefixes(self, inclusive_prefixes)?;
        Ok(canonicalize_element(self, &HashMap::new(), prefixes.as_ref())?.into_bytes())
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    #[must_use]
    pub fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    #[must_use]
    pub fn attributes(&self) -> &[(String, String)] {
        &self.attributes
    }

    #[must_use]
    pub fn children(&self) -> &[Node] {
        &self.children
    }

    /// Return a cloned element retaining only direct children accepted by
    /// `keep`. The parsed element itself remains immutable and cannot be
    /// changed by callers.
    #[must_use]
    pub fn retaining_children(&self, keep: impl Fn(&Node) -> bool) -> Self {
        let mut clone = self.clone();
        clone.children.retain(keep);
        clone
    }

    pub(crate) fn without_ds_signature_nodes(&self) -> Self {
        let mut clone = self.clone();
        clone.children = self
            .children
            .iter()
            .filter_map(|node| match node {
                Node::Element(element)
                    if element.name == "Signature" && element.namespace() == Some(NS_DS) =>
                {
                    None
                }
                Node::Element(element) => Some(Node::Element(element.without_ds_signature_nodes())),
                Node::Text(text) => Some(Node::Text(text.clone())),
            })
            .collect();
        clone
    }

    #[must_use]
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value.as_str()))
    }

    pub fn child_elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|node| match node {
            Node::Element(element) => Some(element),
            Node::Text(_) => None,
        })
    }

    /// Find a direct child by local name and its exact namespace URI.
    ///
    /// `None` means that the child must be unqualified; it is not a wildcard.
    /// Callers processing untrusted XML must always select a namespace
    /// explicitly instead of relying on a local-name-only match.
    #[must_use]
    pub fn find_child_in_namespace(&self, namespace: Option<&str>, name: &str) -> Option<&Element> {
        self.child_elements()
            .find(|child| child.name == name && child.namespace.as_deref() == namespace)
    }

    #[must_use]
    pub fn text_content(&self) -> Option<String> {
        let text = self
            .children
            .iter()
            .filter_map(|node| match node {
                Node::Text(value) => Some(value.as_str()),
                Node::Element(_) => None,
            })
            .collect::<String>();
        (!text.is_empty()).then_some(text)
    }
}

impl TryFrom<&str> for UnverifiedElement {
    type Error = XmlSecurityError;

    fn try_from(xml: &str) -> Result<Self, Self::Error> {
        Self::parse_unverified(xml)
    }
}

impl TryFrom<&String> for UnverifiedElement {
    type Error = XmlSecurityError;

    fn try_from(xml: &String) -> Result<Self, Self::Error> {
        Self::try_from(xml.as_str())
    }
}

#[derive(Clone)]
pub enum Node {
    Element(Element),
    Text(String),
}

impl fmt::Debug for Node {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Element(element) => formatter.debug_tuple("Element").field(element).finish(),
            Self::Text(_) => formatter.debug_tuple("Text").field(&"<redacted>").finish(),
        }
    }
}

pub(crate) fn parse_xml_to_element(xml: &str) -> Result<Element, XmlSecurityError> {
    parse_with_limits(xml, XmlLimits::default())
}

pub(crate) fn parse_with_limits(xml: &str, limits: XmlLimits) -> Result<Element, XmlSecurityError> {
    if limits.max_bytes() == 0 || limits.max_depth() == 0 {
        return Err(XmlSecurityError::Shape {
            message: "XML limits must be non-zero".to_string(),
        });
    }
    if xml.len() > limits.max_bytes() {
        return Err(XmlSecurityError::Shape {
            message: "XML exceeds configured byte limit".to_string(),
        });
    }
    validate_namespace_resource_limits(xml, limits)?;
    let mut config = ParserConfig::new();
    config.whitespace_to_characters = true;
    config.cdata_to_characters = true;
    config.trim_whitespace = false;
    config.ignore_comments = false;
    config.coalesce_characters = true;
    config.allow_multiple_root_elements = false;
    config.max_attributes = limits.max_attributes_per_element();
    config.max_attribute_length = limits.max_bytes();
    config.max_data_length = limits.max_bytes();
    config.max_name_length = limits.max_bytes();
    let reader = EventReader::new_with_config(Cursor::new(xml), config);
    let mut stack = Vec::new();
    let mut root = None;
    let mut element_count = 0;
    for event in reader {
        let event = event.map_err(|_| XmlSecurityError::Parse {
            message: "XML parser rejected the document".to_string(),
        })?;
        match event {
            XmlEvent::StartDocument {
                version, encoding, ..
            } => {
                if version != XmlVersion::Version10 {
                    return Err(XmlSecurityError::Unsupported {
                        message: "Unsupported XML version; only XML 1.0 is supported".to_string(),
                    });
                }
                if !encoding.eq_ignore_ascii_case("UTF-8") {
                    return Err(XmlSecurityError::Unsupported {
                        message: "Unsupported XML encoding; only UTF-8 is supported".to_string(),
                    });
                }
            }
            XmlEvent::Doctype { .. } => {
                return Err(XmlSecurityError::Unsupported {
                    message: "DOCTYPE is not supported".to_string(),
                });
            }
            XmlEvent::ProcessingInstruction { .. } => {
                return Err(XmlSecurityError::Unsupported {
                    message: "Processing instructions are not supported".to_string(),
                });
            }
            XmlEvent::Comment(_) => {
                return Err(XmlSecurityError::Unsupported {
                    message: "comments are not supported".to_string(),
                });
            }
            XmlEvent::StartElement {
                name,
                attributes,
                namespace,
            } => {
                if stack.len() >= limits.max_depth() {
                    return Err(XmlSecurityError::Shape {
                        message: format!("XML exceeds max depth of {}", limits.max_depth()),
                    });
                }
                if element_count >= limits.max_elements() {
                    return Err(XmlSecurityError::Shape {
                        message: format!(
                            "XML exceeds max element count of {}",
                            limits.max_elements()
                        ),
                    });
                }
                if namespace.0.len() > limits.max_namespace_bindings_per_element() {
                    return Err(XmlSecurityError::Shape {
                        message: format!(
                            "XML exceeds max namespace bindings per element of {}",
                            limits.max_namespace_bindings_per_element()
                        ),
                    });
                }
                element_count += 1;
                let mut seen = HashSet::new();
                let mut parsed_attributes = Vec::with_capacity(attributes.len());
                let mut attribute_namespaces = Vec::with_capacity(attributes.len());
                for attribute in attributes {
                    let lexical_key = attribute.name.prefix.as_ref().map_or_else(
                        || attribute.name.local_name.clone(),
                        |prefix| format!("{prefix}:{}", attribute.name.local_name),
                    );
                    let expanded_key = (
                        attribute.name.namespace.clone().unwrap_or_default(),
                        attribute.name.local_name.clone(),
                    );
                    if !seen.insert(expanded_key) {
                        return Err(XmlSecurityError::Shape {
                            message: format!("duplicate attribute: {lexical_key}"),
                        });
                    }
                    parsed_attributes.push((lexical_key, attribute.value));
                    attribute_namespaces.push(attribute.name.namespace);
                }
                let namespace_context: HashMap<String, String> = namespace
                    .iter()
                    .map(|(prefix, uri)| (prefix.to_string(), uri.to_string()))
                    .collect();
                for (prefix, uri) in &namespace_context {
                    if !uri.is_empty() && !is_absolute_namespace_uri(uri) {
                        return Err(XmlSecurityError::Shape {
                            message: format!(
                                "namespace URI for prefix {prefix:?} must be absolute"
                            ),
                        });
                    }
                }
                stack.push(Element {
                    name: name.local_name,
                    namespace: name.namespace.clone(),
                    prefix: name.prefix,
                    attributes: parsed_attributes,
                    attribute_namespaces,
                    children: Vec::new(),
                    ns_uri: name.namespace,
                    namespace_context,
                });
            }
            XmlEvent::EndElement { .. } => {
                let Some(element) = stack.pop() else {
                    return Err(XmlSecurityError::Shape {
                        message: "unexpected closing element".to_string(),
                    });
                };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(Node::Element(element));
                } else if root.replace(element).is_some() {
                    return Err(XmlSecurityError::Shape {
                        message: "multiple root elements".to_string(),
                    });
                }
            }
            XmlEvent::Characters(text) => {
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(Node::Text(text));
                }
            }
            XmlEvent::EndDocument => {}
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err(XmlSecurityError::Shape {
            message: "unclosed XML element".to_string(),
        });
    }
    root.ok_or_else(|| XmlSecurityError::Shape {
        message: "no root element found".to_string(),
    })
}

#[derive(Clone, Copy)]
enum XmlTagKind {
    Start,
    End,
    Other,
}

#[derive(Clone, Copy)]
struct NamespaceDeclaration<'xml> {
    prefix: &'xml [u8],
    uri_bytes: usize,
}

#[derive(Clone, Copy)]
struct NamespaceBinding<'xml> {
    prefix: &'xml [u8],
    uri_bytes: usize,
}

#[derive(Clone)]
struct NamespaceScope<'xml> {
    bindings: Vec<NamespaceBinding<'xml>>,
    uri_bytes: usize,
}

fn validate_namespace_resource_limits(
    xml: &str,
    limits: XmlLimits,
) -> Result<(), XmlSecurityError> {
    let bytes = xml.as_bytes();
    let mut cursor = 0;
    let mut scopes = Vec::new();
    let mut declaration_bytes = 0;
    let mut context_bytes = 0;
    while let Some((kind, start, end)) = next_tag(bytes, &mut cursor) {
        match kind {
            XmlTagKind::Start => {
                let declarations = parse_namespace_declarations(bytes, start, end, limits)?;
                let declaration_bytes_in_tag =
                    declarations.iter().try_fold(0usize, |total, declaration| {
                        total.checked_add(declaration.uri_bytes).ok_or_else(|| {
                            XmlSecurityError::Shape {
                                message: "namespace declaration byte count overflow".to_string(),
                            }
                        })
                    })?;
                declaration_bytes = checked_namespace_sum(
                    declaration_bytes,
                    declaration_bytes_in_tag,
                    limits.max_namespace_declaration_bytes(),
                    "XML exceeds cumulative namespace declaration byte limit",
                )?;
                let scope = extend_namespace_scope(
                    scopes.last(),
                    &declarations,
                    limits.max_namespace_bindings_per_element(),
                )?;
                context_bytes = checked_namespace_sum(
                    context_bytes,
                    scope.uri_bytes,
                    limits.max_namespace_context_bytes(),
                    "XML exceeds cumulative namespace context byte limit",
                )?;
                if !is_self_closing_tag(bytes, end) {
                    scopes.push(scope);
                }
            }
            XmlTagKind::End => {
                scopes.pop();
            }
            XmlTagKind::Other => {}
        }
    }
    Ok(())
}

fn next_tag(bytes: &[u8], cursor: &mut usize) -> Option<(XmlTagKind, usize, usize)> {
    while *cursor < bytes.len() {
        let offset = bytes[*cursor..].iter().position(|byte| *byte == b'<')?;
        let start = *cursor + offset;
        if bytes[start..].starts_with(b"<![CDATA[") {
            let content_start = start + b"<![CDATA[".len();
            let end = bytes
                .get(content_start..)?
                .windows(3)
                .position(|window| window == b"]]>")?;
            *cursor = content_start + end + 3;
            continue;
        }
        let end = unquoted_tag_end(bytes, start)?;
        *cursor = end + 1;
        let kind = match bytes.get(start + 1).copied() {
            Some(b'/') => XmlTagKind::End,
            Some(b'!') | Some(b'?') | None => XmlTagKind::Other,
            Some(byte) if byte.is_ascii_whitespace() => XmlTagKind::Other,
            Some(_) => XmlTagKind::Start,
        };
        return Some((kind, start, end));
    }
    None
}

fn unquoted_tag_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut quote = None;
    for (offset, byte) in bytes[start + 1..].iter().copied().enumerate() {
        match quote {
            Some(expected) if byte == expected => quote = None,
            None if byte == b'\'' || byte == b'"' => quote = Some(byte),
            None if byte == b'>' => return Some(start + 1 + offset),
            _ => {}
        }
    }
    None
}

fn parse_namespace_declarations(
    bytes: &[u8],
    start: usize,
    end: usize,
    limits: XmlLimits,
) -> Result<Vec<NamespaceDeclaration<'_>>, XmlSecurityError> {
    let mut cursor = start + 1;
    while cursor < end && !bytes[cursor].is_ascii_whitespace() && bytes[cursor] != b'/' {
        cursor += 1;
    }
    let mut declarations = HashSet::new();
    let mut parsed = Vec::new();
    while cursor < end {
        while cursor < end && (bytes[cursor].is_ascii_whitespace() || bytes[cursor] == b'/') {
            cursor += 1;
        }
        if cursor >= end {
            break;
        }
        let name_start = cursor;
        while cursor < end
            && !bytes[cursor].is_ascii_whitespace()
            && !matches!(bytes[cursor], b'=' | b'/')
        {
            cursor += 1;
        }
        let name = &bytes[name_start..cursor];
        while cursor < end && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= end || bytes[cursor] != b'=' {
            cursor += usize::from(cursor < end);
            continue;
        }
        cursor += 1;
        while cursor < end && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= end || !matches!(bytes[cursor], b'\'' | b'"') {
            break;
        }
        let quote = bytes[cursor];
        cursor += 1;
        let value_start = cursor;
        while cursor < end && bytes[cursor] != quote {
            cursor += 1;
        }
        if cursor >= end {
            break;
        }
        if is_namespace_declaration(name) {
            if !declarations.insert(name) {
                return Err(XmlSecurityError::Shape {
                    message: format!(
                        "duplicate namespace declaration: {}",
                        String::from_utf8_lossy(name)
                    ),
                });
            }
            let uri_bytes = cursor - value_start;
            if uri_bytes > limits.max_namespace_uri_bytes() {
                return Err(XmlSecurityError::Shape {
                    message: format!(
                        "namespace URI exceeds configured byte limit of {}",
                        limits.max_namespace_uri_bytes()
                    ),
                });
            }
            parsed.push(NamespaceDeclaration {
                prefix: namespace_prefix(name),
                uri_bytes,
            });
        }
        cursor += 1;
    }
    Ok(parsed)
}

fn is_namespace_declaration(name: &[u8]) -> bool {
    name == b"xmlns" || name.starts_with(b"xmlns:")
}

fn namespace_prefix(name: &[u8]) -> &[u8] {
    if name == b"xmlns" {
        &[]
    } else {
        &name[b"xmlns:".len()..]
    }
}

fn extend_namespace_scope<'xml>(
    parent: Option<&NamespaceScope<'xml>>,
    declarations: &[NamespaceDeclaration<'xml>],
    max_bindings: usize,
) -> Result<NamespaceScope<'xml>, XmlSecurityError> {
    let mut scope = parent.cloned().unwrap_or_else(initial_namespace_scope);
    for declaration in declarations {
        if let Some(index) = scope
            .bindings
            .iter()
            .position(|binding| binding.prefix == declaration.prefix)
        {
            let previous = scope.bindings[index].uri_bytes;
            scope.uri_bytes = scope
                .uri_bytes
                .checked_sub(previous)
                .and_then(|remaining| remaining.checked_add(declaration.uri_bytes))
                .ok_or_else(|| XmlSecurityError::Shape {
                    message: "namespace context byte count overflow".to_string(),
                })?;
            scope.bindings[index].uri_bytes = declaration.uri_bytes;
        } else {
            scope.uri_bytes = scope
                .uri_bytes
                .checked_add(declaration.uri_bytes)
                .ok_or_else(|| XmlSecurityError::Shape {
                    message: "namespace context byte count overflow".to_string(),
                })?;
            scope.bindings.push(NamespaceBinding {
                prefix: declaration.prefix,
                uri_bytes: declaration.uri_bytes,
            });
        }
    }
    if scope.bindings.len() > max_bindings {
        return Err(XmlSecurityError::Shape {
            message: format!("XML exceeds max namespace bindings per element of {max_bindings}"),
        });
    }
    Ok(scope)
}

fn initial_namespace_scope<'xml>() -> NamespaceScope<'xml> {
    NamespaceScope {
        bindings: vec![
            NamespaceBinding {
                prefix: b"xml",
                uri_bytes: NS_XML.len(),
            },
            NamespaceBinding {
                prefix: b"xmlns",
                uri_bytes: NS_XMLNS.len(),
            },
            NamespaceBinding {
                prefix: &[],
                uri_bytes: 0,
            },
        ],
        uri_bytes: NS_XML.len() + NS_XMLNS.len(),
    }
}

fn is_self_closing_tag(bytes: &[u8], end: usize) -> bool {
    let mut cursor = end;
    while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }
    cursor > 0 && bytes[cursor - 1] == b'/'
}

fn checked_namespace_sum(
    total: usize,
    additional: usize,
    limit: usize,
    message: &str,
) -> Result<usize, XmlSecurityError> {
    let next = total
        .checked_add(additional)
        .ok_or_else(|| XmlSecurityError::Shape {
            message: message.to_string(),
        })?;
    if next > limit {
        return Err(XmlSecurityError::Shape {
            message: message.to_string(),
        });
    }
    Ok(next)
}

pub(crate) fn extract_in_response_to(xml: &str) -> Result<Option<String>, XmlSecurityError> {
    let element = parse_xml_to_element(xml)?;
    if element.name != "Response" || element.namespace.as_deref() != Some(SAML_PROTOCOL_NS) {
        return Err(XmlSecurityError::NamespaceMismatch {
            message: "root element must be samlp:Response".to_string(),
        });
    }
    Ok(element.attr("InResponseTo").map(ToOwned::to_owned))
}

/// Extract a value from parsed XML without asserting that the document is
/// signed or that the value is covered by a signature.
pub fn extract_unverified_in_response_to(xml: &str) -> Result<Option<String>, XmlSecurityError> {
    extract_in_response_to(xml)
}

pub(crate) fn canonicalize_xml(element: &Element) -> Result<Vec<u8>, XmlSecurityError> {
    Ok(canonicalize_element(element, &HashMap::new(), None)?.into_bytes())
}

pub(crate) fn canonicalize_exclusive(
    xml: &str,
    inclusive_prefixes: Option<&[&str]>,
) -> Result<Vec<u8>, XmlSecurityError> {
    let element = parse_xml_to_element(xml)?;
    let prefixes = validate_inclusive_prefixes(&element, inclusive_prefixes)?;
    Ok(canonicalize_element(&element, &HashMap::new(), prefixes.as_ref())?.into_bytes())
}

/// Parse and canonicalise attacker-controlled XML without performing any
/// signature verification.
pub fn canonicalize_unverified_xml_text(
    xml: &str,
    inclusive_prefixes: &[&str],
) -> Result<Vec<u8>, XmlSecurityError> {
    canonicalize_exclusive(xml, Some(inclusive_prefixes))
}

fn validate_inclusive_prefixes(
    element: &Element,
    prefixes: Option<&[&str]>,
) -> Result<Option<HashSet<String>>, XmlSecurityError> {
    let Some(prefixes) = prefixes else {
        return Ok(None);
    };
    let mut normalized_prefixes = HashSet::with_capacity(prefixes.len());
    for prefix in prefixes {
        let normalized = if *prefix == "#default" {
            String::new()
        } else {
            if !is_namespace_prefix(prefix) {
                return Err(XmlSecurityError::NamespaceMismatch {
                    message: format!("invalid inclusive namespace prefix: {prefix}"),
                });
            }
            (*prefix).to_string()
        };
        if !normalized_prefixes.insert(normalized.clone()) {
            return Err(XmlSecurityError::NamespaceMismatch {
                message: format!("duplicate inclusive namespace prefix: {prefix}"),
            });
        }
        let declared_uri = element.namespace_context.get(&normalized);
        if declared_uri.is_none() || declared_uri.is_some_and(String::is_empty) {
            return Err(XmlSecurityError::NamespaceMismatch {
                message: format!(
                    "inclusive prefix is not declared on the canonical root: {prefix}"
                ),
            });
        }
    }
    Ok(Some(normalized_prefixes))
}

fn is_namespace_prefix(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix != "xml"
        && prefix != "xmlns"
        && prefix.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
}

fn is_absolute_namespace_uri(uri: &str) -> bool {
    if uri
        .chars()
        .any(|character| character.is_ascii_control() || character.is_ascii_whitespace())
    {
        return false;
    }
    let Some((scheme, _)) = uri.split_once(':') else {
        return false;
    };
    let mut characters = scheme.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
}

fn canonicalize_element(
    element: &Element,
    parent_namespaces: &HashMap<String, String>,
    inclusive_prefixes: Option<&HashSet<String>>,
) -> Result<String, XmlSecurityError> {
    let mut namespaces = parent_namespaces.clone();
    namespaces
        .entry("xml".to_string())
        .or_insert_with(|| NS_XML.to_string());
    let mut in_scope = element.namespace_context.clone();
    for (prefix, uri) in parent_namespaces {
        in_scope
            .entry(prefix.clone())
            .or_insert_with(|| uri.clone());
    }
    let mut used = HashSet::new();
    if let Some(prefix) = &element.prefix {
        used.insert(prefix.clone());
    } else if element.ns_uri.is_some() || namespaces.get("").is_some_and(|uri| !uri.is_empty()) {
        used.insert(String::new());
    }
    for (name, _) in &element.attributes {
        if let Some((prefix, _)) = name.split_once(':')
            && prefix != "xmlns"
        {
            used.insert(prefix.to_string());
        }
    }
    if let Some(prefixes) = inclusive_prefixes {
        for prefix in prefixes {
            let declared_here = if prefix.is_empty() {
                element.ns_uri.is_some() || in_scope.contains_key("")
            } else {
                in_scope.contains_key(prefix)
            };
            if declared_here {
                used.insert(prefix.clone());
            }
        }
    }
    let mut namespace_attributes = Vec::new();
    for prefix in used {
        let uri = if prefix.is_empty() {
            in_scope
                .get("")
                .cloned()
                .or_else(|| {
                    element
                        .prefix
                        .is_none()
                        .then(|| element.ns_uri.clone())
                        .flatten()
                })
                .unwrap_or_default()
        } else {
            in_scope.get(&prefix).cloned().unwrap_or_default()
        };
        if namespaces.get(&prefix) != Some(&uri) {
            namespaces.insert(prefix.clone(), uri.clone());
            let name = if prefix.is_empty() {
                "xmlns".to_string()
            } else {
                format!("xmlns:{prefix}")
            };
            namespace_attributes.push((name, uri));
        }
    }
    namespace_attributes.sort_by(|left, right| left.0.cmp(&right.0));
    let mut regular = element
        .attributes
        .iter()
        .enumerate()
        .filter(|(_, (name, _))| name != "xmlns" && !name.starts_with("xmlns:"))
        .map(|(index, (name, value))| {
            let namespace = element
                .attribute_namespaces
                .get(index)
                .and_then(Clone::clone)
                .unwrap_or_default();
            let local_name = name
                .rsplit_once(':')
                .map_or(name.as_str(), |(_, local)| local);
            (
                namespace,
                local_name.to_owned(),
                name.clone(),
                value.clone(),
            )
        })
        .collect::<Vec<_>>();
    regular.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let mut output = String::new();
    output.push('<');
    if let Some(prefix) = &element.prefix {
        output.push_str(prefix);
        output.push(':');
    }
    output.push_str(&element.name);
    for (name, value) in namespace_attributes.into_iter() {
        output.push(' ');
        output.push_str(&name);
        output.push_str("=\"");
        append_attribute_value(&mut output, &value);
        output.push('"');
    }
    for (_, _, name, value) in regular {
        output.push(' ');
        output.push_str(&name);
        output.push_str("=\"");
        append_attribute_value(&mut output, &value);
        output.push('"');
    }
    output.push('>');
    for child in &element.children {
        match child {
            Node::Element(child) => output.push_str(&canonicalize_element(
                child,
                &namespaces,
                inclusive_prefixes,
            )?),
            Node::Text(text) => append_text_value(&mut output, text),
        }
    }
    output.push_str("</");
    if let Some(prefix) = &element.prefix {
        output.push_str(prefix);
        output.push(':');
    }
    output.push_str(&element.name);
    output.push('>');
    Ok(output)
}

fn append_attribute_value(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '"' => output.push_str("&quot;"),
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '\t' => output.push_str("&#x9;"),
            '\n' => output.push_str("&#xA;"),
            '\r' => output.push_str("&#xD;"),
            _ => output.push(character),
        }
    }
}

fn append_text_value(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\r' => output.push_str("&#xD;"),
            _ => output.push(character),
        }
    }
}
