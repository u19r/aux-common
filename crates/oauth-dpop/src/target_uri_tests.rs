use crate::DpopTargetUri;

#[test]
fn given_rfc3986_equivalent_targets_when_comparing_then_normalizes_only_permitted_equivalences() {
    for (left, right) in [
        ("HTTPS://EXAMPLE.COM:443", "https://example.com/"),
        ("https://example.com/a/../b", "https://example.com/b"),
        (
            "https://example.com/%7e/a/%2e%2E/b?query=1#fragment",
            "https://example.com/~/b",
        ),
        ("https://example.com/a%2fb", "https://example.com/a%2Fb"),
        ("https://[2001:DB8::1]:443/a", "https://[2001:db8::1]/a"),
    ] {
        assert_eq!(
            DpopTargetUri::try_from(left).unwrap(),
            DpopTargetUri::try_from(right).unwrap()
        );
    }
    for (left, right) in [
        ("https://example.com/a%2Fb", "https://example.com/a/b"),
        ("https://example.com/a//b", "https://example.com/a/b"),
        ("https://example.com/a/", "https://example.com/a"),
        ("https://example.com:444/a", "https://example.com/a"),
    ] {
        assert_ne!(
            DpopTargetUri::try_from(left).unwrap(),
            DpopTargetUri::try_from(right).unwrap()
        );
    }
}

#[test]
fn given_invalid_or_untrusted_uri_forms_when_constructing_then_rejects_and_joins_one_boundary_slash()
 {
    for target in [
        "http://localhost/a",
        "/a",
        "https://user:password@example.com/a",
        "https://example.com:/a",
        "https://example.com:99999/a",
        "https://example.com:invalid/a",
        "https://example.com/%",
        "https://example.com/%GG",
        "https://exämple.com/a",
        "https://example.com/\\a",
        "https://example.com/a b",
        "https://exa%mple.com/a",
    ] {
        assert!(DpopTargetUri::try_from(target).is_err());
    }
    for base in ["https://example.com/?a", "https://example.com/#f"] {
        assert!(DpopTargetUri::parse_base(base).is_err());
    }
    let base = DpopTargetUri::parse_base("https://example.com/prefix/").unwrap();
    assert_eq!(
        base.join_path("/a//b/").unwrap().as_str(),
        "https://example.com/prefix/a//b/"
    );
}

#[test]
fn given_public_base_when_resolving_origin_and_absolute_requests_then_preserves_the_exact_external_path()
 {
    let base = DpopTargetUri::parse_base("https://resource.example/prefix/").unwrap();
    for request in [
        "/a?ignored=one",
        "https://resource.example/prefix/a?ignored=one",
    ] {
        assert_eq!(
            base.resolve_request_uri(&request.parse().unwrap())
                .unwrap()
                .as_str(),
            "https://resource.example/prefix/a"
        );
    }
    for request in [
        "https://attacker.example/prefix/a",
        "http://resource.example/prefix/a",
        "https://resource.example/prefix-other/a",
    ] {
        assert!(base.resolve_request_uri(&request.parse().unwrap()).is_err());
    }
    let root = DpopTargetUri::parse_base("https://resource.example/").unwrap();
    assert_eq!(
        root.resolve_request_uri(&"//a".parse().unwrap())
            .unwrap()
            .as_str(),
        "https://resource.example//a"
    );
    let repeated = DpopTargetUri::parse_base("https://resource.example/prefix//").unwrap();
    assert_eq!(
        repeated.join_path("/a").unwrap().as_str(),
        "https://resource.example/prefix//a"
    );
    assert!(
        repeated
            .resolve_request_uri(&"https://resource.example/prefix/a".parse().unwrap())
            .is_err()
    );
    assert_eq!(
        repeated
            .resolve_request_uri(&"https://resource.example/prefix//a".parse().unwrap())
            .unwrap()
            .as_str(),
        "https://resource.example/prefix//a"
    );
    let maximum = format!("https://a.example/{}", "a".repeat(8192 - 18));
    assert_eq!(maximum.len(), 8192);
    assert!(DpopTargetUri::try_from(maximum.as_str()).is_ok());
    assert!(DpopTargetUri::try_from(format!("{maximum}a").as_str()).is_err());
}
