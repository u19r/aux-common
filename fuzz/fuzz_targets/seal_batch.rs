#![no_main]

use buffered_writes::{
    AtomicSink, BufferedWrites, EnvelopeKey, SealedBatch, SealedBatchInput, SinkError, SinkLimits,
    TenantScope, WriteAttempt,
};
use libfuzzer_sys::fuzz_target;

// Authenticated queue envelope oracle over replayed queue bytes.
//
// `EnvelopeKey::open` is the decode site of every replayed queue message:
// serde deserialization through `BatchEnvelope` with digest verification,
// version, identity and membership gates, then a constant-time HMAC check.
// The batch digest is unkeyed and detects corruption only; the envelope tag
// is the authentication boundary over the queue hop. The oracle:
// 1. hostile bytes never panic the decoder;
// 2. a mutated authentic envelope decodes only to the identical batch;
// 3. a batch rewritten for a fuzz-chosen scope, with its digest recomputed,
//    never opens under the authentic tag or under another key's tag;
// 4. the authentic seed round-trips identity and digest.
fuzz_target!(|data: &[u8]| {
    let key = envelope_key();
    let seed_batch = run_once();
    let seed = key
        .seal(seed_batch.clone())
        .expect("seed envelope encodes")
        .bytes()
        .to_vec();

    let mut envelope = seed.clone();
    let mut cursor = 0;
    let mut edits = 0;
    while edits < 12 && cursor + 4 <= data.len() && !envelope.is_empty() {
        let position =
            usize::from(u16::from_le_bytes([data[cursor + 1], data[cursor + 2]])) % envelope.len();
        match data[cursor] % 6 {
            0 => envelope[position] ^= 1,
            1 => envelope.insert(position, 0),
            2 => envelope.truncate(envelope.len().saturating_sub(1)),
            3 => {
                let inserted = envelope[position];
                envelope.insert(position, inserted ^ 0x80);
            }
            4 => {
                let witness = (position + 7) % envelope.len();
                envelope.swap(position, witness);
            }
            _ => envelope.reverse(),
        }
        cursor += 4;
        edits += 1;
    }
    if let Ok(batch) = key.open(&envelope) {
        assert_eq!(batch, seed_batch, "a mutated envelope decoded to another batch");
    }

    if let Some(scope) = fuzz_scope(data) {
        let value = serde_json::to_value(&seed_batch).expect("seed batch encodes");
        let mut input: SealedBatchInput =
            serde_json::from_value(value).expect("seed batch input decodes");
        input.scope = scope;
        if let Ok(forged) = SealedBatch::try_new(input)
            && forged != seed_batch
        {
            let seed_value: serde_json::Value =
                serde_json::from_slice(&seed).expect("seed envelope is JSON");
            let pasted_tag = serde_json::to_vec(
                &serde_json::json!({"mac": seed_value["mac"], "batch": forged}),
            )
            .expect("forged envelope encodes");
            assert!(key.open(&pasted_tag).is_err(), "forged scope accepted");
            let other_key = EnvelopeKey::try_new([0x5a; 32]).expect("other key");
            let resealed = other_key.seal(forged).expect("forged envelope encodes");
            assert!(key.open(resealed.bytes()).is_err(), "foreign key accepted");
        }
    }

    let restored = key.open(&seed).expect("seed envelope opens");
    assert_eq!(restored, seed_batch);
    assert!(restored.verify_digest());
});

fn envelope_key() -> EnvelopeKey {
    EnvelopeKey::try_new([0x42; 32]).expect("envelope key")
}

/// Maps fuzz bytes onto the scope alphabet; invalid scopes are skipped.
fn fuzz_scope(data: &[u8]) -> Option<TenantScope> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";
    let scope = data
        .iter()
        .take(32)
        .map(|byte| char::from(ALPHABET[usize::from(*byte) % ALPHABET.len()]))
        .collect::<String>();
    TenantScope::try_new(scope).ok()
}

/// One authentic sealed batch through the production writer (fixture path
/// mirrors `envelopes.rs`).
fn run_once() -> SealedBatch {
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        let sender = sender.clone();
        async move {
            let _ = sender.send(attempt.sealed_batch().clone());
            Ok::<(), SinkError>(())
        }
    })
    .expect("sink");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let writer = BufferedWrites::builder("envelope/v1", sink)
            .build()
            .unwrap();
        writer.add_write_item(61).await.unwrap();
        writer.flush_writes().await;
    });
    receiver.try_recv().expect("sealed batch")
}
