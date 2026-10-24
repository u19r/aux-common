mod decoder;

pub use decoder::{CoseKey, parse_cose_key};
pub(crate) use decoder::{
    decode_bounded_cbor, ensure_canonical_cbor, validate_canonical_map_order,
};

#[cfg(test)]
mod decoder_tests;
