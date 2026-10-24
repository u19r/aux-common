//! Validation and UTC evaluation for portable five-field cron expressions.

use core::{
    hash::{Hash, Hasher},
    str::FromStr,
};
use std::num::NonZeroU16;

use chrono::{DateTime, Utc};

use super::Timestamp;
use crate::error::ValidationError;

/// A validated portable five-field UTC cron expression.
#[derive(Clone, Debug, Eq)]
pub struct CronExpression {
    canonical: String,
    schedule: cron::Schedule,
}

impl CronExpression {
    /// Maximum accepted UTF-8 bytes in the complete expression. The bound is
    /// checked before tokenization or the third-party cron parser runs.
    pub const MAX_INPUT_BYTES: usize = 256;
    /// Maximum UTF-8 bytes in one of the five portable fields.
    pub const MAX_FIELD_BYTES: usize = 128;
    /// Maximum comma-separated segments across all five fields.
    pub const MAX_SEGMENTS: usize = 32;

    pub fn try_new(expression: impl AsRef<str>) -> Result<Self, ValidationError> {
        let input = expression.as_ref();
        let fields = validate_cron_fields(input)?;
        let canonical = fields.join(" ");
        let schedule = parse_cron_schedule(fields)?;
        Ok(Self {
            canonical,
            schedule,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Returns the first UTC occurrence strictly after `after`.
    pub fn next_after(&self, after: Timestamp) -> Result<Option<Timestamp>, ValidationError> {
        let datetime = timestamp_to_utc(after)?;
        self.schedule
            .after(&datetime)
            .next()
            .map(timestamp_from_utc)
            .transpose()
    }

    /// Returns the first UTC occurrence at or after `at`.
    pub fn next_at_or_after(&self, at: Timestamp) -> Result<Option<Timestamp>, ValidationError> {
        let preceding = at
            .as_millis()
            .checked_sub(1)
            .map(Timestamp::from_millis)
            .unwrap_or(at);
        self.next_after(preceding)
    }

    /// Returns at most `limit` occurrences in `(after, through]`.
    pub fn occurrences_until(
        &self,
        after: Timestamp,
        through: Timestamp,
        limit: NonZeroU16,
    ) -> Result<Vec<Timestamp>, ValidationError> {
        if through <= after {
            return Ok(Vec::new());
        }
        let mut result = Vec::new();
        let mut cursor = after;
        while result.len() < usize::from(limit.get()) {
            let Some(next) = self.next_after(cursor)? else {
                break;
            };
            if next > through {
                break;
            }
            result.push(next);
            cursor = next;
        }
        Ok(result)
    }
}

fn validate_cron_fields(input: &str) -> Result<[&str; 5], ValidationError> {
    if input.len() > CronExpression::MAX_INPUT_BYTES {
        return Err(ValidationError::TooLong {
            field: "cron expression",
            maximum: CronExpression::MAX_INPUT_BYTES,
            actual: input.len(),
        });
    }
    let mut fields = [""; 5];
    let mut segment_count = 0;
    for (field_count, field) in input.split_ascii_whitespace().enumerate() {
        let slot = fields
            .get_mut(field_count)
            .ok_or(ValidationError::InvalidValue {
                field: "cron expression",
            })?;
        if field.len() > CronExpression::MAX_FIELD_BYTES {
            return Err(ValidationError::TooLong {
                field: "cron field",
                maximum: CronExpression::MAX_FIELD_BYTES,
                actual: field.len(),
            });
        }
        segment_count += field.split(',').count();
        if segment_count > CronExpression::MAX_SEGMENTS {
            return Err(ValidationError::TooLong {
                field: "cron segments",
                maximum: CronExpression::MAX_SEGMENTS,
                actual: segment_count,
            });
        }
        *slot = field;
    }
    if fields.iter().any(|field| field.is_empty())
        || fields.iter().any(|field| has_portable_extension(field))
    {
        return Err(ValidationError::InvalidValue {
            field: "cron expression",
        });
    }
    Ok(fields)
}

fn parse_cron_schedule(fields: [&str; 5]) -> Result<cron::Schedule, ValidationError> {
    // `cron` uses the Quartz-style 1..=7 weekday domain (Sunday is 1),
    // while the portable five-field contract uses the POSIX 0..=7
    // domain (Sunday is 0 or 7). Keep the persisted spelling canonical
    // and adapt only the parser input at this boundary.
    let parser_fields =
        normalize_parser_weekday(fields[4]).ok_or(ValidationError::InvalidValue {
            field: "cron expression",
        })?;
    let parser_input = format!(
        "0 {} {} {} {} {} *",
        fields[0], fields[1], fields[2], fields[3], parser_fields
    );
    let schedule =
        cron::Schedule::from_str(&parser_input).map_err(|_| ValidationError::InvalidValue {
            field: "cron expression",
        })?;
    Ok(schedule)
}

impl PartialEq for CronExpression {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Hash for CronExpression {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

impl FromStr for CronExpression {
    type Err = ValidationError;

    fn from_str(expression: &str) -> Result<Self, Self::Err> {
        Self::try_new(expression)
    }
}

fn has_portable_extension(field: &str) -> bool {
    field.starts_with('@')
        || field.contains('?')
        || field.contains('L')
        || field.contains('W')
        || field.contains('#')
}

fn normalize_parser_weekday(field: &str) -> Option<String> {
    field
        .split(',')
        .map(normalize_weekday_part)
        .collect::<Option<Vec<_>>>()
        .map(|parts| parts.join(","))
}

fn normalize_weekday_part(part: &str) -> Option<String> {
    let (base, step) = part
        .split_once('/')
        .map_or((part, None), |(base, step)| (base, Some(step)));
    let normalized = if let Some((start, end)) = base.split_once('-') {
        normalize_weekday_range(start, end, step)?
    } else if base == "*" {
        base.to_owned()
    } else if let Ok(number) = base.parse::<u8>() {
        normalize_weekday_number(number)?.to_string()
    } else {
        // The imported parser owns named weekday validation and semantics;
        // only its numeric domain needs adaptation.
        base.to_owned()
    };
    if base.contains('-') {
        Some(normalized)
    } else {
        step.map_or(Some(normalized.clone()), |step| {
            Some(format!("{normalized}/{step}"))
        })
    }
}

fn normalize_weekday_range(start: &str, end: &str, step: Option<&str>) -> Option<String> {
    let (Ok(start), Ok(end)) = (start.parse::<u8>(), end.parse::<u8>()) else {
        // Preserve named ranges for the imported parser, which owns their
        // validation. Numeric ranges are expanded below because Sunday has
        // two spellings in the portable domain.
        return Some(match step {
            Some(step) => format!("{start}-{end}/{step}"),
            None => format!("{start}-{end}"),
        });
    };
    if start > end {
        return None;
    }
    let step = step.map_or(Some(1), |value| value.parse::<u8>().ok());
    let step = step.filter(|value| *value > 0)?;
    let mut values = Vec::new();
    let mut value = start;
    loop {
        let normalized = normalize_weekday_number(value)?;
        if !values.contains(&normalized) {
            values.push(normalized);
        }
        if value > end.saturating_sub(step) {
            break;
        }
        value = value.saturating_add(step);
    }
    Some(
        values
            .into_iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(","),
    )
}

fn normalize_weekday_number(value: u8) -> Option<u8> {
    match value {
        0 | 7 => Some(1),
        1..=6 => Some(value + 1),
        _ => None,
    }
}

fn timestamp_to_utc(timestamp: Timestamp) -> Result<DateTime<Utc>, ValidationError> {
    DateTime::from_timestamp_millis(timestamp.as_millis()).ok_or(ValidationError::Overflow {
        field: "cron timestamp",
    })
}

fn timestamp_from_utc(datetime: DateTime<Utc>) -> Result<Timestamp, ValidationError> {
    Ok(Timestamp::from_millis(datetime.timestamp_millis()))
}
