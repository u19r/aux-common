use crate::{
    constants::{DEFAULT_BATCH_MAX_BYTES, DEFAULT_BATCH_MAX_ITEMS},
    error::{ConfigurationError, PrepareError},
};

/// Native destination limits supplied by a [`crate::WriteSink`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SinkLimits {
    max_operations: usize,
    max_payload_bytes: usize,
    receipt_overhead_bytes: usize,
    effect_expansion_factor: usize,
}

impl Default for SinkLimits {
    fn default() -> Self {
        Self {
            max_operations: DEFAULT_BATCH_MAX_ITEMS,
            max_payload_bytes: DEFAULT_BATCH_MAX_BYTES,
            receipt_overhead_bytes: 0,
            effect_expansion_factor: 1,
        }
    }
}

impl SinkLimits {
    pub fn try_new(
        max_operations: usize,
        max_payload_bytes: usize,
    ) -> Result<Self, ConfigurationError> {
        let limits = Self {
            max_operations,
            max_payload_bytes,
            receipt_overhead_bytes: 0,
            effect_expansion_factor: 1,
        };
        limits.validate()?;
        Ok(limits)
    }

    #[must_use]
    pub const fn with_receipt_overhead_bytes(mut self, bytes: usize) -> Self {
        self.receipt_overhead_bytes = bytes;
        self
    }

    /// Upper-bound byte expansion from each prepared payload to destination
    /// effects. Operation limits use prepared-operation units; the adapter
    /// derives that limit after reserving native operation overhead and
    /// per-operation effect counts.
    #[must_use]
    pub const fn with_effect_expansion_factor(mut self, factor: usize) -> Self {
        self.effect_expansion_factor = factor;
        self
    }

    #[must_use]
    pub const fn max_operations(&self) -> usize {
        self.max_operations
    }

    #[must_use]
    pub const fn max_payload_bytes(&self) -> usize {
        self.max_payload_bytes
    }

    #[must_use]
    pub const fn receipt_overhead_bytes(&self) -> usize {
        self.receipt_overhead_bytes
    }

    #[must_use]
    pub const fn effect_expansion_factor(&self) -> usize {
        self.effect_expansion_factor
    }

    pub(crate) fn expanded_payload_bytes(&self, raw_bytes: usize) -> usize {
        raw_bytes
            .saturating_mul(self.effect_expansion_factor)
            .saturating_add(self.receipt_overhead_bytes)
    }

    pub(crate) fn raw_payload_limit(&self) -> usize {
        self.max_payload_bytes
            .saturating_sub(self.receipt_overhead_bytes)
            .checked_div(self.effect_expansion_factor)
            .unwrap_or(0)
    }

    pub(crate) fn validate_prepared_size(
        &self,
        count: usize,
        raw_bytes: usize,
    ) -> Result<(), PrepareError> {
        if count == 0 {
            return Err(PrepareError::EmptyOperations);
        }
        if count > self.max_operations {
            return Err(PrepareError::TooManyOperations {
                count,
                limit: self.max_operations,
            });
        }
        let size = self.expanded_payload_bytes(raw_bytes);
        if size > self.max_payload_bytes {
            return Err(PrepareError::CandidateTooLarge {
                size,
                limit: self.max_payload_bytes,
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ConfigurationError> {
        if self.max_operations == 0 || self.max_payload_bytes == 0 {
            return Err(ConfigurationError::ZeroCapacity {
                field: "sink_limits",
            });
        }
        if self.effect_expansion_factor == 0
            || self.receipt_overhead_bytes >= self.max_payload_bytes
        {
            return Err(ConfigurationError::InvalidSinkLimits {
                reason: "invalid expansion factor or receipt overhead",
            });
        }
        Ok(())
    }
}
