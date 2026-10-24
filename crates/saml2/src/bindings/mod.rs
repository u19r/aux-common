mod codec;

pub use codec::{
    build_redirect_request_url, decode_post_request, decode_redirect_request, encode_response,
    validate_redirect_destination,
};

#[cfg(test)]
mod codec_tests;
