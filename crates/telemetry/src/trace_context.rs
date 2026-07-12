use std::fmt;

use http::{HeaderMap, HeaderValue};
use uuid::Uuid;

use crate::constants::{HEADER_REQUEST_ID, HEADER_TRACE_ID, HEADER_TRACEPARENT, HEADER_TRACESTATE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceId([u8; 32]);

impl TraceId {
    #[must_use]
    pub fn generate() -> Self {
        Self(hex_array_from_bytes::<16, 32>(Uuid::new_v4().as_bytes()))
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::parse_exact(value.trim())
    }

    fn parse_exact(value: &str) -> Option<Self> {
        Some(Self(parse_hex_ascii_array::<32>(value)?))
    }

    fn parse_exact_bytes(value: &[u8]) -> Option<Self> {
        Some(Self(parse_hex_ascii_array_from_bytes::<32>(value)?))
    }

    fn header_value(&self) -> Option<HeaderValue> {
        HeaderValue::from_bytes(&self.0).ok()
    }

    #[must_use]
    pub fn to_hex_string(&self) -> String {
        let mut value = String::with_capacity(32);
        self.write_hex_to(&mut value);
        value
    }

    pub fn write_hex_to(&self, output: &mut String) {
        push_ascii_bytes(output, &self.0);
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_ascii_bytes(f, &self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanId([u8; 16]);

impl SpanId {
    #[must_use]
    pub fn generate() -> Self {
        let raw = Uuid::new_v4().as_u128();
        let value = ((raw >> 64) as u64) ^ (raw as u64);
        if value == 0 {
            return Self(*b"0000000000000001");
        }
        Self(hex_array_from_bytes::<8, 16>(&value.to_be_bytes()))
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::parse_exact(value.trim())
    }

    fn parse_exact(value: &str) -> Option<Self> {
        Some(Self(parse_hex_ascii_array::<16>(value)?))
    }

    fn parse_exact_bytes(value: &[u8]) -> Option<Self> {
        Some(Self(parse_hex_ascii_array_from_bytes::<16>(value)?))
    }

    #[must_use]
    pub fn to_hex_string(&self) -> String {
        let mut value = String::with_capacity(16);
        self.write_hex_to(&mut value);
        value
    }

    pub fn write_hex_to(&self, output: &mut String) {
        push_ascii_bytes(output, &self.0);
    }
}

impl fmt::Display for SpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_ascii_bytes(f, &self.0)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TraceFlags(u8);

impl TraceFlags {
    pub const DEFAULT: Self = Self(0);

    pub fn parse(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.len() != 2 || !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        u8::from_str_radix(trimmed, 16).ok().map(Self)
    }

    fn parse_exact_bytes(value: &[u8]) -> Option<Self> {
        if value.len() != 2 {
            return None;
        }
        Some(Self(
            (decode_hex_nibble(value[0])? << 4) | decode_hex_nibble(value[1])?,
        ))
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self.0
    }

    fn write_hex(self, output: &mut String) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        output.push(HEX[usize::from(self.0 >> 4)] as char);
        output.push(HEX[usize::from(self.0 & 0x0f)] as char);
    }

    fn write_hex_bytes(self, output: &mut [u8; 2]) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        output[0] = HEX[usize::from(self.0 >> 4)];
        output[1] = HEX[usize::from(self.0 & 0x0f)];
    }
}

impl fmt::Display for TraceFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}", self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceContext {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub parent_span_id: Option<SpanId>,
    pub trace_flags: TraceFlags,
    trace_state: Option<HeaderValue>,
    request_id: Option<HeaderValue>,
    pub parent_trace_id: Option<TraceId>,
}

impl TraceContext {
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let parsed = traceparent_from_headers(headers);
        let request_id = headers
            .get(HEADER_REQUEST_ID)
            .filter(|value| !trim_ascii_bytes(value.as_bytes()).is_empty())
            .cloned();

        if let Some(parsed) = parsed {
            let parent_trace_id = parsed.trace_id;
            let trace_state = trace_state_from_headers(headers);
            return Self {
                trace_id: parsed.trace_id,
                span_id: SpanId::generate(),
                parent_span_id: Some(parsed.parent_span_id),
                trace_flags: parsed.trace_flags,
                trace_state,
                request_id,
                parent_trace_id: Some(parent_trace_id),
            };
        }

        if let Some(legacy_trace_id) = headers
            .get(HEADER_TRACE_ID)
            .and_then(|value| TraceId::parse_exact_bytes(trim_ascii_bytes(value.as_bytes())))
        {
            let parent_trace_id = legacy_trace_id;
            return Self {
                trace_id: legacy_trace_id,
                span_id: SpanId::generate(),
                parent_span_id: None,
                trace_flags: TraceFlags::default(),
                trace_state: None,
                request_id,
                parent_trace_id: Some(parent_trace_id),
            };
        }

        Self {
            trace_id: TraceId::generate(),
            span_id: SpanId::generate(),
            parent_span_id: None,
            trace_flags: TraceFlags::default(),
            trace_state: None,
            request_id,
            parent_trace_id: None,
        }
    }

    #[must_use]
    pub fn traceparent(&self) -> String {
        let mut value = String::with_capacity(55);
        value.push_str("00-");
        self.trace_id.write_hex_to(&mut value);
        value.push('-');
        self.span_id.write_hex_to(&mut value);
        value.push('-');
        self.trace_flags.write_hex(&mut value);
        value
    }

    pub fn write_forward_headers(&self, headers: &mut HeaderMap) {
        if let Some(value) = self.traceparent_header_value() {
            headers.insert(HEADER_TRACEPARENT, value);
        }
        if let Some(trace_state) = &self.trace_state {
            headers.insert(HEADER_TRACESTATE, trace_state.clone());
        }
        if let Some(value) = self.trace_id.header_value() {
            headers.insert(HEADER_TRACE_ID, value);
        }
        if let Some(request_id) = &self.request_id {
            headers.insert(HEADER_REQUEST_ID, request_id.clone());
        }
    }

    #[must_use]
    pub fn trace_state_str(&self) -> Option<&str> {
        self.trace_state
            .as_ref()
            .and_then(|value| value.to_str().ok())
    }

    #[must_use]
    pub fn request_id_str(&self) -> Option<&str> {
        self.request_id
            .as_ref()
            .and_then(|value| value.to_str().ok())
    }

    fn traceparent_header_value(&self) -> Option<HeaderValue> {
        let mut bytes = [0_u8; 55];
        bytes[..3].copy_from_slice(b"00-");
        bytes[3..35].copy_from_slice(&self.trace_id.0);
        bytes[35] = b'-';
        bytes[36..52].copy_from_slice(&self.span_id.0);
        bytes[52] = b'-';
        let mut flags = [0_u8; 2];
        self.trace_flags.write_hex_bytes(&mut flags);
        bytes[53..55].copy_from_slice(&flags);
        HeaderValue::from_bytes(&bytes).ok()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedTraceparent {
    trace_id: TraceId,
    parent_span_id: SpanId,
    trace_flags: TraceFlags,
}

fn traceparent_from_headers(headers: &HeaderMap) -> Option<ParsedTraceparent> {
    parse_traceparent_bytes(headers.get(HEADER_TRACEPARENT)?.as_bytes())
}

fn parse_traceparent_bytes(bytes: &[u8]) -> Option<ParsedTraceparent> {
    let bytes = trim_ascii_bytes(bytes);
    if bytes.len() < 55 {
        return None;
    }
    let version = (decode_hex_nibble(bytes[0])? << 4) | decode_hex_nibble(bytes[1])?;
    if version == u8::MAX
        || (version == 0 && bytes.len() != 55)
        || (version > 0 && bytes.len() > 55 && (bytes[55] != b'-' || bytes.len() == 56))
        || bytes[2] != b'-'
        || bytes[35] != b'-'
        || bytes[52] != b'-'
    {
        return None;
    }
    Some(ParsedTraceparent {
        trace_id: TraceId::parse_exact_bytes(&bytes[3..35])?,
        parent_span_id: SpanId::parse_exact_bytes(&bytes[36..52])?,
        trace_flags: TraceFlags::parse_exact_bytes(&bytes[53..55])?,
    })
}

fn trace_state_from_headers(headers: &HeaderMap) -> Option<HeaderValue> {
    headers
        .get(HEADER_TRACESTATE)
        .filter(|value| !trim_ascii_bytes(value.as_bytes()).is_empty())
        .cloned()
}

fn trim_ascii_bytes(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if !first.is_ascii_whitespace() {
            break;
        }
        bytes = rest;
    }
    while let Some((last, rest)) = bytes.split_last() {
        if !last.is_ascii_whitespace() {
            break;
        }
        bytes = rest;
    }
    bytes
}

fn parse_hex_ascii_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    parse_hex_ascii_array_from_bytes(value.as_bytes())
}

fn parse_hex_ascii_array_from_bytes<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    if bytes.len() != N {
        return None;
    }

    let mut has_non_zero = false;
    let mut output = [0_u8; N];
    for index in 0..N {
        output[index] = canonical_hex_byte(bytes[index])?;
        has_non_zero |= output[index] != b'0';
    }
    has_non_zero.then_some(output)
}

fn canonical_hex_byte(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' | b'a'..=b'f' => Some(byte),
        b'A'..=b'F' => Some(byte.to_ascii_lowercase()),
        _ => None,
    }
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_array_from_bytes<const IN: usize, const OUT: usize>(bytes: &[u8; IN]) -> [u8; OUT] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = [0_u8; OUT];
    for (index, byte) in bytes.iter().enumerate() {
        output[index * 2] = HEX[usize::from(byte >> 4)];
        output[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    output
}

fn push_ascii_bytes(output: &mut String, bytes: &[u8]) {
    if let Ok(value) = std::str::from_utf8(bytes) {
        output.push_str(value);
    }
}

fn write_ascii_bytes(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    let value = std::str::from_utf8(bytes).map_err(|_| fmt::Error)?;
    formatter.write_str(value)
}
