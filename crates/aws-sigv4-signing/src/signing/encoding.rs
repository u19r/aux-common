use url::form_urlencoded;

pub(super) fn encode_component(value: &[u8]) -> String {
    let mut encoded = String::new();
    for byte in value {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(*byte));
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

pub(super) fn canonical_query(query: Option<&str>, added: &[(String, String)]) -> String {
    let mut pairs: Vec<_> = form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .map(|(key, value)| {
            (
                encode_component(key.as_bytes()),
                encode_component(value.as_bytes()),
            )
        })
        .chain(added.iter().map(|(key, value)| {
            (
                encode_component(key.as_bytes()),
                encode_component(value.as_bytes()),
            )
        }))
        .collect();
    pairs.sort_unstable();
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

pub(super) fn canonical_path(path: &str, is_s3: bool) -> String {
    if path.is_empty() {
        return "/".to_owned();
    }
    if is_s3 {
        return path.to_owned();
    }
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(encode_component(other.as_bytes())),
        }
    }
    let mut normalized = format!("/{}", segments.join("/"));
    if ["/", "/.", "/.."]
        .iter()
        .any(|suffix| path.ends_with(suffix))
        && !normalized.ends_with('/')
    {
        normalized.push('/');
    }
    normalized
}
