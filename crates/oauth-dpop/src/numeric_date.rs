use serde::Deserialize;
use serde_json::value::RawValue;

use crate::{DpopError, constants::MAX_NUMERIC_DATE_SECONDS};

/// Exact comparison against whole-second bounds, without binary floating point.
#[derive(Default)]
pub(super) struct NumericDate {
    seconds: i64,
    has_fraction: bool,
}

impl NumericDate {
    pub(super) fn parse_payload(payload: &[u8]) -> Result<Self, DpopError> {
        #[derive(Deserialize)]
        struct Claims<'a> {
            #[serde(borrow)]
            iat: &'a RawValue,
        }
        let claims: Claims<'_> =
            serde_json::from_slice(payload).map_err(|_| DpopError::InvalidProof)?;
        Self::parse_number(claims.iat.get())
    }

    pub(super) fn is_between(&self, minimum: i64, maximum: i64) -> bool {
        self.seconds >= minimum
            && (self.seconds < maximum || self.seconds == maximum && !self.has_fraction)
    }

    fn parse_number(number: &str) -> Result<Self, DpopError> {
        let (mantissa, exponent) = split_exponent(number)?;
        let negative = mantissa.starts_with('-');
        let mantissa = mantissa.strip_prefix('-').unwrap_or(mantissa);
        let decimal_position = mantissa.find('.').unwrap_or(mantissa.len());
        let digits: String = mantissa
            .chars()
            .filter(|character| *character != '.')
            .collect();
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(DpopError::InvalidProof);
        }
        if negative && digits.bytes().any(|byte| byte != b'0') {
            return Err(DpopError::InvalidProof);
        }
        let first_nonzero = digits.bytes().position(|byte| byte != b'0');
        let Some(first_nonzero) = first_nonzero else {
            return Ok(Self::default());
        };
        let integer_end = decimal_position as i64 + exponent;
        let seconds = parse_seconds(&digits, first_nonzero, integer_end)?;
        let fraction_start =
            usize::try_from(integer_end.max(0)).map_err(|_| DpopError::InvalidProof)?;
        let has_fraction = digits
            .as_bytes()
            .get(fraction_start..)
            .is_some_and(|suffix| suffix.iter().any(|byte| *byte != b'0'));
        if seconds > MAX_NUMERIC_DATE_SECONDS || seconds == MAX_NUMERIC_DATE_SECONDS && has_fraction
        {
            return Err(DpopError::InvalidProof);
        }
        Ok(Self {
            seconds,
            has_fraction,
        })
    }
}

fn split_exponent(number: &str) -> Result<(&str, i64), DpopError> {
    let Some((mantissa, exponent)) = number.split_once(['e', 'E']) else {
        return Ok((number, 0));
    };
    let negative = exponent.starts_with('-');
    let digits = exponent.trim_start_matches(['+', '-']);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DpopError::InvalidProof);
    }
    let magnitude = digits.bytes().fold(0_i64, |value, digit| {
        (value * 10 + i64::from(digit - b'0')).min(100_000)
    });
    Ok((mantissa, if negative { -magnitude } else { magnitude }))
}

fn parse_seconds(digits: &str, first_nonzero: usize, integer_end: i64) -> Result<i64, DpopError> {
    let significant_integer_digits = integer_end - first_nonzero as i64;
    if significant_integer_digits > 12 {
        return Err(DpopError::InvalidProof);
    }
    let mut seconds = 0_i64;
    for index in first_nonzero as i64..integer_end {
        let digit = digits
            .as_bytes()
            .get(index as usize)
            .copied()
            .unwrap_or(b'0');
        seconds = seconds * 10 + i64::from(digit - b'0');
    }
    Ok(seconds)
}
