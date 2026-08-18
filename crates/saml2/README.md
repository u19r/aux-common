# saml2

saml2 implements a strict, model-neutral SAML 2.0 subset: bounded HTTP-POST
request/response encoding and request decoding, HTTP-Redirect request
decoding, safe destination validation, caller-timed
metadata parsing, X.509 public-key extraction, SHA-256 digesting, and RSA
PKCS#1 v1.5 with SHA-256 signature verification.

The accepted XML Signature URIs are exactly
`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` and
`http://www.w3.org/2001/04/xmlenc#sha256`; URI parsing is case-sensitive and
unsupported algorithms fail closed.

Metadata requires future `validUntil` values on both an `EntitiesDescriptor`
wrapper and the selected `EntityDescriptor`, a non-blank entity ID, exactly one
HTTPS HTTP-POST SSO location, and an X.509 signing certificate at the exact
`KeyDescriptor` → `KeyInfo` → `X509Data` path. Encryption-only, omitted, or
unknown key uses, ambiguous endpoints or key containers, remote
`RetrievalMethod` keys, embedded metadata signatures, XInclude, and XML
Encryption are rejected; certificate parsing never establishes trust.

It does not own tenant IDs, IdP persistence, metadata fetching, replay stores,
assertion semantics, RelayState policy, or trust-anchor selection. Unsupported
bindings, algorithms, transforms, malformed certificates, expired metadata,
and resource-limit violations fail closed. Parsed metadata and certificates are
read-only values.
