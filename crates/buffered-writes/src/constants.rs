use std::time::Duration;

pub(crate) const DEFAULT_FLUSH_MAX_AGE: Duration = Duration::from_millis(200);
pub(crate) const DEFAULT_FLUSH_MAX_ITEMS: usize = 25;

pub(crate) const DEFAULT_BUFFER_MAX_ITEMS: usize = 25;
pub(crate) const DEFAULT_BUFFER_MAX_BYTES: usize = 8 * 1024 * 1024;

pub(crate) const DEFAULT_BATCH_MAX_ITEMS: usize = 25;
pub(crate) const DEFAULT_BATCH_MAX_BYTES: usize = 64 * 1024;

pub(crate) const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
pub(crate) const DEFAULT_FLUSH_BUDGET: Duration = Duration::from_secs(2);
pub(crate) const DEFAULT_SUBMIT_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const DEFAULT_MAX_ATTEMPTS_PER_TURN: u32 = 3;
pub(crate) const DEFAULT_RETRY_BASE_DELAY: Duration = Duration::from_millis(50);
pub(crate) const DEFAULT_RETRY_MAX_DELAY: Duration = Duration::from_millis(500);

pub(crate) const DEFAULT_BREAKER_FAILURE_THRESHOLD: u32 = 5;
pub(crate) const DEFAULT_FALLBACK_AGE_THRESHOLD: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_PROBE_INITIAL_DELAY: Duration = Duration::from_secs(1);
pub(crate) const DEFAULT_PROBE_MAX_DELAY: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_RECOVERY_SUCCESS_THRESHOLD: u32 = 3;

pub(crate) const DEFAULT_LEASE_DURATION: Duration = Duration::from_secs(5);
pub(crate) const DEFAULT_LEASE_SAFETY_MARGIN: Duration = Duration::from_millis(500);
pub(crate) const DEFAULT_SHUTDOWN_SAFETY_MARGIN: Duration = Duration::from_millis(100);
#[cfg(feature = "lambda")]
pub(crate) const LAMBDA_SHUTDOWN_SAFETY_MARGIN: Duration = Duration::from_millis(150);
#[cfg(feature = "lambda")]
pub(crate) const LAMBDA_EXTERNAL_EXTENSION_MAX_SHUTDOWN: Duration = Duration::from_millis(2_000);

pub(crate) const MAX_NAMESPACE_BYTES: usize = 256;
pub(crate) const MAX_SCOPE_BYTES: usize = 256;
pub(crate) const MAX_OPERATION_ID_BYTES: usize = 256;
pub(crate) const MAX_VERSION_BYTES: usize = 128;

pub(crate) const DEFAULT_CODEC_VERSION: &str = "serde-json/v1";
pub(crate) const RAW_BYTES_CODEC_VERSION: &str = "raw-bytes/v1";
pub(crate) const DEFAULT_GROUPING_STRATEGY_VERSION: &str = "default-items/v1";

pub(crate) const ARC_ALLOCATION_HEADER_BYTES: usize = 2 * std::mem::size_of::<usize>();
pub(crate) const RETENTION_ENTRY_OVERHEAD_BYTES: usize = 64;
pub(crate) const MAX_COMPLETED_OPERATION_RECEIPTS: usize = 4_096;

#[cfg(feature = "disk")]
pub(crate) const DISK_JOURNAL_MAGIC: &[u8; 8] = b"AUXBWJ01";
#[cfg(feature = "disk")]
pub(crate) const DISK_JOURNAL_VERSION: u16 = 8;

#[cfg(feature = "valkey")]
pub(crate) const VALKEY_STATE_VERSION: u16 = 6;
#[cfg(feature = "disk")]
pub(crate) const DISK_JOURNAL_FILE_NAME: &str = "journal.bin";
#[cfg(feature = "disk")]
pub(crate) const DISK_JOURNAL_COMPACT_FILE_NAME: &str = "journal.compact.bin";
#[cfg(feature = "disk")]
pub(crate) const DISK_JOURNAL_LOCK_FILE_NAME: &str = "journal.lock";
#[cfg(feature = "disk")]
pub(crate) const DISK_FRAME_HEADER_BYTES: usize = 13;
#[cfg(feature = "disk")]
pub(crate) const MAX_DISK_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[cfg(feature = "valkey")]
pub(crate) const VALKEY_MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;
#[cfg(feature = "valkey")]
pub(crate) const VALKEY_SCAN_COUNT: usize = 64;

pub(crate) const SQS_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
#[cfg(feature = "sqs")]
pub(crate) const SQS_DEFAULT_VISIBILITY_TIMEOUT_SECS: u32 = 30;
#[cfg(feature = "sqs")]
pub(crate) const SQS_SERVICE_NAME: &str = "sqs";
#[cfg(feature = "sqs")]
pub(crate) const SQS_JSON_CONTENT_TYPE: &str = "application/x-amz-json-1.0";
#[cfg(feature = "sqs")]
pub(crate) const SQS_TARGET_HEADER: &str = "x-amz-target";
#[cfg(feature = "sqs")]
pub(crate) const SQS_TARGET_SEND_MESSAGE: &str = "AmazonSQS.SendMessage";
#[cfg(feature = "sqs")]
pub(crate) const SQS_TARGET_RECEIVE_MESSAGE: &str = "AmazonSQS.ReceiveMessage";
#[cfg(feature = "sqs")]
pub(crate) const SQS_TARGET_DELETE_MESSAGE: &str = "AmazonSQS.DeleteMessage";
#[cfg(feature = "sqs")]
pub(crate) const SQS_TARGET_CHANGE_VISIBILITY: &str = "AmazonSQS.ChangeMessageVisibility";

#[cfg(feature = "lambda")]
pub(crate) const LAMBDA_IPC_MAX_MESSAGE_BYTES: usize = 1024 * 1024;

#[cfg(feature = "tokio")]
pub(crate) const DEFAULT_SPOT_POLL_INTERVAL: Duration = Duration::from_secs(5);

pub(crate) const BATCH_DIGEST_DOMAIN: &[u8] = b"aux-buffered-writes/batch/v2";
pub(crate) const ADMISSION_DIGEST_DOMAIN: &[u8] = b"aux-buffered-writes/admission/v1";

#[cfg(feature = "valkey")]
pub(crate) const VALKEY_REVISION_PREFIX_BYTES: usize = b"{\"_revision\":\"".len() + 36 + 1;

#[cfg(feature = "valkey")]
pub(crate) const VALKEY_STATE_SCRIPT: &str = r#"
local mode = ARGV[1]
local limit = tonumber(ARGV[2])
local prefix_end = tonumber(ARGV[3]) - 1
local state_exists = redis.call('EXISTS', KEYS[1])
local metadata_exists = redis.call('EXISTS', KEYS[2])
if mode == 'commit' and (state_exists ~= tonumber(ARGV[4]) or metadata_exists ~= tonumber(ARGV[5])) then return 0 end
local memory = redis.call('INFO', 'memory')
if not string.find(memory, 'maxmemory_policy:noeviction', 1, true) then
    return redis.error_reply('AUX_BUFFER_POLICY noeviction required')
end
if state_exists ~= metadata_exists then return redis.error_reply('AUX_BUFFER_CORRUPT incomplete pair') end
if state_exists == 1 and (redis.call('PTTL', KEYS[1]) ~= -1 or redis.call('PTTL', KEYS[2]) ~= -1) then
    return redis.error_reply('AUX_BUFFER_CORRUPT expiring retained data')
end
if redis.call('STRLEN', KEYS[1]) > limit or redis.call('STRLEN', KEYS[2]) > limit then
    return redis.error_reply('AUX_BUFFER_CORRUPT oversized value')
end
if state_exists == 1 and redis.call('GETRANGE', KEYS[1], 0, prefix_end) ~= redis.call('GETRANGE', KEYS[2], 0, prefix_end) then
    return redis.error_reply('AUX_BUFFER_CORRUPT mismatching revision')
end
if mode == 'read' then return redis.call('MGET', KEYS[1], KEYS[2]) end
if mode == 'inspect' then return {state_exists, redis.call('GET', KEYS[2])} end
if mode ~= 'commit' then return redis.error_reply('AUX_BUFFER_CORRUPT invalid operation') end
if ARGV[4] == '1' and redis.call('GET', KEYS[1]) ~= ARGV[6] then return 0 end
if ARGV[5] == '1' and redis.call('GET', KEYS[2]) ~= ARGV[7] then return 0 end
local deadline = tonumber(ARGV[10])
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
if deadline > 0 and now_ms >= deadline then return 0 end
if #ARGV[8] > limit or #ARGV[9] > limit then return redis.error_reply('AUX_BUFFER_FULL oversized commit') end
redis.call('MSET', KEYS[1], ARGV[8], KEYS[2], ARGV[9])
return 1
"#;

pub(crate) const REPLAY_QUARANTINE_VERSION: u16 = 1;

#[cfg(feature = "sqs")]
pub(crate) const SQS_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[cfg(feature = "sqs")]
pub(crate) const SQS_MAX_VISIBILITY_TIMEOUT_SECS: u64 = 43_200;

#[cfg(feature = "tokio")]
pub(crate) const DEFAULT_SPOT_SHUTDOWN_CAP: Duration = Duration::from_secs(120);
#[cfg(feature = "tokio")]
pub(crate) const MIN_SPOT_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[cfg(feature = "ec2")]
pub(crate) const DEFAULT_IMDS_ENDPOINT: &str = "http://169.254.169.254";
#[cfg(feature = "ec2")]
pub(crate) const DEFAULT_IMDS_POLL_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(feature = "ec2")]
pub(crate) const IMDS_TOKEN_PATH: &str = "/latest/api/token";
#[cfg(feature = "ec2")]
pub(crate) const IMDS_ACTION_PATH: &str = "/latest/meta-data/spot/instance-action";
#[cfg(feature = "ec2")]
pub(crate) const IMDS_TOKEN_HEADER: &str = "x-aws-ec2-metadata-token";
#[cfg(feature = "ec2")]
pub(crate) const IMDS_TOKEN_TTL_HEADER: &str = "x-aws-ec2-metadata-token-ttl-seconds";
#[cfg(feature = "ec2")]
pub(crate) const IMDS_TOKEN_TTL_SECONDS: &str = "21600";
#[cfg(feature = "ec2")]
pub(crate) const IMDS_TOKEN_REFRESH_AFTER: Duration = Duration::from_secs(21540);
#[cfg(feature = "ec2")]
pub(crate) const IMDS_MAX_TOKEN_BYTES: usize = 8192;
#[cfg(feature = "ec2")]
pub(crate) const IMDS_MAX_NOTICE_BYTES: usize = 16384;

#[cfg(feature = "lambda")]
pub(crate) const LAMBDA_IPC_DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(feature = "lambda")]
pub(crate) const LAMBDA_IPC_MAX_TOKEN_BYTES: usize = 256;
#[cfg(feature = "lambda")]
pub(crate) const LAMBDA_MAX_INVOCATION_ID_BYTES: usize = 128;
#[cfg(feature = "lambda")]
pub(crate) const LAMBDA_IPC_VERSION: u16 = 2;

#[cfg(feature = "lambda")]
pub(crate) const LAMBDA_API_INIT_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(feature = "lambda")]
pub(crate) const LAMBDA_API_BODY_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(feature = "lambda")]
pub(crate) const LAMBDA_API_MAX_BODY_BYTES: usize = 64 * 1024;
#[cfg(feature = "lambda")]
pub(crate) const LAMBDA_API_MAX_IDENTIFIER_BYTES: usize = 256;
#[cfg(feature = "lambda")]
pub(crate) const LAMBDA_EXTENSION_REGISTER_PATH: &str = "/2020-01-01/extension/register";
#[cfg(feature = "lambda")]
pub(crate) const LAMBDA_EXTENSION_NEXT_PATH: &str = "/2020-01-01/extension/event/next";
#[cfg(feature = "lambda")]
pub(crate) const LAMBDA_EXTENSION_REGISTER_BODY: &str = r#"{"events":["INVOKE","SHUTDOWN"]}"#;
