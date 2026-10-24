use url::Url;

use crate::{
    ConfigurationError, QueueConfig, QueueLimits, constants::SQS_MAX_MESSAGE_BYTES,
    queue::QueueConfigKind,
};

pub(super) struct SqsConfiguration {
    pub(super) primary: QueueAddress,
    pub(super) endpoint_override: Option<String>,
    pub(super) quarantine: Option<QueueAddress>,
    pub(super) fifo_group_id: Option<String>,
    pub(super) is_fifo: bool,
    pub(super) limits: QueueLimits,
}

impl TryFrom<QueueConfig> for SqsConfiguration {
    type Error = ConfigurationError;

    fn try_from(config: QueueConfig) -> Result<Self, Self::Error> {
        let QueueConfigKind::Sqs {
            queue_url,
            endpoint,
            region,
            quarantine_url,
            fifo_group_id,
            max_envelope_bytes,
        } = config.inner
        else {
            return Err(ConfigurationError::InvalidQueueConfiguration {
                reason: "expected SQS queue configuration",
            });
        };
        if let Some(endpoint) = &endpoint {
            validate_endpoint(endpoint)?;
        }
        let parsed = validate_sqs_url(&queue_url, endpoint.is_some())?;
        let region = resolve_region(region, &parsed)?;
        let quarantine = validate_quarantine(
            &parsed,
            quarantine_url.as_deref(),
            endpoint.is_some(),
            &region,
        )?;
        let is_fifo = parsed.path().ends_with(".fifo");
        validate_fifo_group(fifo_group_id.as_deref(), is_fifo)?;
        Ok(Self {
            primary: QueueAddress::from_validated(queue_url, &parsed, region),
            endpoint_override: endpoint,
            quarantine,
            fifo_group_id,
            is_fifo,
            limits: validate_message_limit(max_envelope_bytes)?,
        })
    }
}

fn validate_endpoint(endpoint: &str) -> Result<(), ConfigurationError> {
    let parsed =
        Url::parse(endpoint).map_err(|_| ConfigurationError::InvalidQueueConfiguration {
            reason: "SQS endpoint override is invalid",
        })?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfigurationError::InvalidQueueConfiguration {
            reason: "SQS endpoint override must be HTTPS without credentials, query or fragment",
        });
    }
    Ok(())
}

fn validate_sqs_url(raw_url: &str, allow_custom_host: bool) -> Result<Url, ConfigurationError> {
    let parsed =
        Url::parse(raw_url).map_err(|_| ConfigurationError::InvalidQueueConfiguration {
            reason: "queue URL is not a valid URL",
        })?;
    if parsed.scheme() != "https" {
        return Err(ConfigurationError::InvalidQueueConfiguration {
            reason: "SQS queue URL must use https",
        });
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfigurationError::InvalidQueueConfiguration {
            reason: "SQS queue URL must not contain userinfo, query, or fragment",
        });
    }
    let segments: Vec<&str> = parsed
        .path_segments()
        .map_or_else(Vec::new, Iterator::collect);
    if segments.len() < 2 || segments.iter().any(|s| s.is_empty()) {
        return Err(ConfigurationError::InvalidQueueConfiguration {
            reason: "SQS queue URL must include account ID and queue name path segments",
        });
    }
    if !allow_custom_host {
        let _ = derive_region_from_sqs_url(&parsed)?;
    }
    Ok(parsed)
}

fn derive_region_from_sqs_url(url: &Url) -> Result<String, ConfigurationError> {
    let Some(host) = url.host_str() else {
        return Err(ConfigurationError::InvalidQueueConfiguration {
            reason: "SQS queue URL is missing host",
        });
    };
    let Some(rest) = host.strip_prefix("sqs.") else {
        return Err(ConfigurationError::InvalidQueueConfiguration {
            reason: "standard SQS host must start with sqs.<region>.",
        });
    };
    let Some((region, suffix)) = rest.split_once('.') else {
        return Err(ConfigurationError::InvalidQueueConfiguration {
            reason: "standard SQS host must contain region segment",
        });
    };
    if region.is_empty() || (suffix != "amazonaws.com" && suffix != "amazonaws.com.cn") {
        return Err(ConfigurationError::InvalidQueueConfiguration {
            reason: "unrecognized standard SQS domain; supply an explicit region override",
        });
    }
    Ok(region.to_owned())
}

fn validate_fifo_group(group: Option<&str>, is_fifo: bool) -> Result<(), ConfigurationError> {
    let Some(group) = group else {
        return Ok(());
    };
    if !is_fifo
        || group.is_empty()
        || group.len() > 128
        || !group.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ConfigurationError::InvalidQueueConfiguration {
            reason: "FIFO group must be 1-128 printable ASCII bytes on a FIFO queue",
        });
    }
    Ok(())
}

fn validate_quarantine(
    source: &Url,
    quarantine: Option<&str>,
    allow_custom_host: bool,
    region: &str,
) -> Result<Option<QueueAddress>, ConfigurationError> {
    let Some(raw_quarantine) = quarantine else {
        return Ok(None);
    };
    let quarantine = validate_sqs_url(raw_quarantine, allow_custom_host)?;
    if quarantine == *source {
        return Err(ConfigurationError::InvalidQueueConfiguration {
            reason: "quarantine must use a separate queue",
        });
    }
    let region = derive_region_from_sqs_url(&quarantine).or_else(|error| {
        if allow_custom_host {
            Ok(region.to_owned())
        } else {
            Err(error)
        }
    })?;
    Ok(Some(QueueAddress::from_validated(
        raw_quarantine.to_owned(),
        &quarantine,
        region,
    )))
}

fn resolve_region(region: Option<String>, queue: &Url) -> Result<String, ConfigurationError> {
    match region {
        Some(region) if !region.trim().is_empty() => Ok(region.trim().to_owned()),
        Some(_) => Err(ConfigurationError::InvalidQueueConfiguration {
            reason: "SQS region must not be empty",
        }),
        None => derive_region_from_sqs_url(queue),
    }
}

fn validate_message_limit(bytes: usize) -> Result<QueueLimits, ConfigurationError> {
    if bytes > SQS_MAX_MESSAGE_BYTES {
        return Err(ConfigurationError::InvalidQueueConfiguration {
            reason: "configured SQS body limit exceeds 1 MiB service maximum",
        });
    }
    QueueLimits::try_new(bytes, true)
}

/// Queue identity stays in the JSON body; AWS JSON requests use the service
/// root.
pub(super) struct QueueAddress {
    pub(super) url: String,
    pub(super) endpoint: String,
    pub(super) region: String,
}

impl QueueAddress {
    fn from_validated(url: String, parsed: &Url, region: String) -> Self {
        Self {
            url,
            endpoint: format!("{}/", parsed.origin().ascii_serialization()),
            region,
        }
    }
}
