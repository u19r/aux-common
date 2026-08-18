# xml-security

xml-security is a bounded XML 1.0/UTF-8 parser and a narrowly documented
canonicalisation primitive for the SAML profile. The default limits are 512 KiB
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
transforms are not implemented. This crate does not verify signatures. Parsed
children must be selected with `Element::find_child_in_namespace`, which compares
both local name and exact namespace URI. Parsed elements expose read-only accessors
and no application or tenant types; debug output redacts text and attribute values.
