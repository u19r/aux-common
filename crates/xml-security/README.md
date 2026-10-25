# xml-security

xml-security provides bounded XML 1.0/UTF-8 parsing, exclusive canonicalisation,
and strict enveloped XML signature verification for the SAML profile. The default limits are 512 KiB
of input, 64 nested elements, 8,192 total elements, 128 attributes per element,
and 64 in-scope namespace bindings per element. Callers with a smaller protocol
profile can use `XmlLimits::try_with_cardinality` to lower any of those bounds.
Namespace URI values are limited to 1 KiB each, declarations to 16 KiB in total,
and the cumulative in-scope namespace context materialised across the document to
4 MiB by default. `XmlLimits::try_with_namespace_bytes` adjusts those budgets for
an explicitly reviewed protocol profile.
It rejects DTDs, processing instructions, comments, unsupported encodings and
versions, duplicate attributes or namespace declarations, relative or
whitespace-containing namespace URIs, multiple roots, and oversized/deep/
high-cardinality documents before callers inspect a partial tree.

The canonicaliser supports the reviewed Exclusive XML Canonicalization subset
(`http://www.w3.org/2001/10/xml-exc-c14n#`) without comments. The optional
inclusive-prefix list is explicit and must name a prefix declared on the canonical
root; a declaration that appears only on a descendant is rejected. XPath, XSLT,
external references, entity expansion, XML Encryption, and unrecognised
transforms are rejected. Parsed
children must be selected with `UnverifiedElement::find_child_in_namespace`, which compares
both local name and exact namespace URI. Parsed elements expose read-only accessors
and no application or tenant types; debug output redacts text and attribute values.

## Signature verification

`VerifiedXmlDocument::verify_enveloped` verifies RSA-SHA256 signatures and SHA-256 reference
digests against caller-supplied trusted public keys. It requires a unique signed element ID,
a same-document reference, and the supported enveloped-signature and exclusive-canonicalisation
transforms. Embedded key material does not establish trust.

Use `signed_element()` or `into_signed_element()` to obtain the verified subtree. A root
signature authenticates the root; otherwise exactly one nested signed target is required.
Signature descendants are removed from the returned subtree. Parsing helpers and
`UnverifiedElement` do not establish authenticity. Callers own key trust, protocol validation,
and application authorization.

When a protocol requires a specific signed element, use
`VerifiedXmlDocument::try_from(EnvelopedSignature::new(xml, trusted_keys).with_target_id(id))`.
Selection uses the original document, preserving namespace context and checking ID uniqueness
throughout the document. The selected element must have its own valid direct signature; an
ancestor signature cannot substitute for it. To require both a response and its assertion to
be signed, verify each ID separately. Each result proves only its selected signature; signature
metadata inside an authenticated subtree does not prove that a nested signature is valid.
`verify_enveloped_with` accepts the same selector with a caller-supplied cryptographic provider.
