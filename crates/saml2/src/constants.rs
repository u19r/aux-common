pub(crate) const MAX_XML_BYTES: usize = 512 * 1024;
pub const MAX_REQUEST_B64_BYTES: usize = MAX_XML_BYTES.div_ceil(3) * 4;
