use super::constants::{VALKEY_MAX_VALUE_BYTES, VALKEY_REVISION_PREFIX_BYTES, VALKEY_STATE_SCRIPT};

#[tokio::test]
#[ignore = "requires BUFFERED_WRITES_REDIS_TEST_URL pointing to a disposable Redis-compatible \
            service"]
async fn given_observed_absence_when_empty_key_appears_then_compare_and_swap_preserves_it() {
    let endpoint = std::env::var("BUFFERED_WRITES_REDIS_TEST_URL").unwrap();
    let client = redis::Client::open(endpoint).unwrap();
    let mut connection = client.get_multiplexed_async_connection().await.unwrap();
    let domain = uuid::Uuid::now_v7();
    let state_key = format!("buffered-writes-cas:{{{domain}}}:state");
    let metadata_key = format!("buffered-writes-cas:{{{domain}}}:metadata");
    for changed_key in [&state_key, &metadata_key] {
        let _: () = redis::cmd("DEL")
            .arg(&state_key)
            .arg(&metadata_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        let previous: (Option<Vec<u8>>, Option<Vec<u8>>) = redis::cmd("MGET")
            .arg(&state_key)
            .arg(&metadata_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(previous, (None, None));
        let _: () = redis::cmd("SET")
            .arg(changed_key)
            .arg(b"")
            .query_async(&mut connection)
            .await
            .unwrap();
        let applied: i64 = redis::Script::new(VALKEY_STATE_SCRIPT)
            .key(&state_key)
            .key(&metadata_key)
            .arg("commit")
            .arg(VALKEY_MAX_VALUE_BYTES)
            .arg(VALKEY_REVISION_PREFIX_BYTES)
            .arg(u8::from(previous.0.is_some()))
            .arg(u8::from(previous.1.is_some()))
            .arg(previous.0.as_deref().unwrap_or_default())
            .arg(previous.1.as_deref().unwrap_or_default())
            .arg(b"new-state")
            .arg(b"new-metadata")
            .arg(0)
            .invoke_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(applied, 0, "CAS overwrote a newly present empty value");
        let after: (Option<Vec<u8>>, Option<Vec<u8>>) = redis::cmd("MGET")
            .arg(&state_key)
            .arg(&metadata_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        let expected = if changed_key == &state_key {
            (Some(vec![]), None)
        } else {
            (None, Some(vec![]))
        };
        assert_eq!(after, expected);
    }
    let _: () = redis::cmd("DEL")
        .arg(state_key)
        .arg(metadata_key)
        .query_async(&mut connection)
        .await
        .unwrap();
}

fn prepare_protocol<'a>(
    script: &'a redis::Script,
    keys: &[String; 2],
    mode: &str,
) -> redis::ScriptInvocation<'a> {
    let mut call = script.prepare_invoke();
    call.key(&keys[0])
        .key(&keys[1])
        .arg(mode)
        .arg(VALKEY_MAX_VALUE_BYTES)
        .arg(VALKEY_REVISION_PREFIX_BYTES);
    call
}

#[tokio::test]
#[ignore = "requires BUFFERED_WRITES_REDIS_TEST_URL pointing to a disposable service"]
async fn given_expired_commit_guard_when_cas_arrives_then_preserve_original_absence() {
    let client =
        redis::Client::open(std::env::var("BUFFERED_WRITES_REDIS_TEST_URL").unwrap()).unwrap();
    let mut connection = client.get_multiplexed_async_connection().await.unwrap();
    let tag = uuid::Uuid::now_v7();
    let keys = [
        format!("buffered-native:{{{tag}}}:state"),
        format!("buffered-native:{{{tag}}}:metadata"),
    ];
    let (seconds, micros): (i64, i64) = redis::cmd("TIME")
        .query_async(&mut connection)
        .await
        .unwrap();
    let past = seconds * 1000 + micros / 1000 - 1;
    let script = redis::Script::new(VALKEY_STATE_SCRIPT);
    let applied: i64 = prepare_protocol(&script, &keys, "commit")
        .arg(0)
        .arg(0)
        .arg(b"")
        .arg(b"")
        .arg(b"new-state")
        .arg(b"new-metadata")
        .arg(past)
        .invoke_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(applied, 0);
    let pair: (Option<Vec<u8>>, Option<Vec<u8>>) = redis::cmd("MGET")
        .arg(&keys)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(pair, (None, None));
}

#[tokio::test]
#[ignore = "requires BUFFERED_WRITES_REDIS_TEST_URL pointing to a disposable service"]
async fn given_oversized_remote_value_when_inspected_then_server_rejects_without_returning_payload()
{
    let client =
        redis::Client::open(std::env::var("BUFFERED_WRITES_REDIS_TEST_URL").unwrap()).unwrap();
    let mut connection = client.get_multiplexed_async_connection().await.unwrap();
    let tag = uuid::Uuid::now_v7();
    let keys = [
        format!("buffered-native:{{{tag}}}:state"),
        format!("buffered-native:{{{tag}}}:metadata"),
    ];
    let _: () = redis::cmd("MSET")
        .arg(&keys[0])
        .arg(vec![b'x'; VALKEY_MAX_VALUE_BYTES + 1])
        .arg(&keys[1])
        .arg(b"metadata")
        .query_async(&mut connection)
        .await
        .unwrap();
    let script = redis::Script::new(VALKEY_STATE_SCRIPT);
    for mode in ["read", "inspect"] {
        let error = prepare_protocol(&script, &keys, mode)
            .invoke_async::<redis::Value>(&mut connection)
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some("AUX_BUFFER_CORRUPT"));
    }
    let length: usize = redis::cmd("STRLEN")
        .arg(&keys[0])
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(length, VALKEY_MAX_VALUE_BYTES + 1);
    let _: () = redis::cmd("DEL")
        .arg(&keys)
        .query_async(&mut connection)
        .await
        .unwrap();
}
