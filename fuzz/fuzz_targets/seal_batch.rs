#![no_main]

use buffered_writes::{AtomicSink, BufferedWrites, SealedBatch, SinkError, SinkLimits, WriteAttempt};
use libfuzzer_sys::fuzz_target;

// Sealed-batch wire envelope oracle over replayed queue bytes.
//
// `SealedBatch::from_envelope_bytes` is the decode site of every replayed
// queue message: serde deserialization through `BatchEnvelope` with digest
// verification, codec/strategy version gates, duplicate operation/record
// identity gates, and membership agreement. The oracle:
// 1. hostile bytes never panic the decoder;
// 2. pasting the seed's authentic digest over mutated content must not
//    decode — the digest is an authentication boundary over the queue hop;
// 3. an Ok decode always round-trips identity and digest so no decode path
//    can tamper with durable record bytes a sink later dispatches.
fuzz_target!(|data: &[u8]| {
    let seed = sealed_envelope_bytes();
    let seed_digest = sealed_envelope_digest();

    let mut envelope = seed.clone();
    let mut cursor = 0;
    let mut edits = 0;
    while edits < 12 && cursor + 4 <= data.len() && !envelope.is_empty() {
        let position =
            usize::from(u16::from_le_bytes([data[cursor + 1], data[cursor + 2]]))
                % envelope.len();
        if matches!(data[cursor] % 6, 0) {
            let index = position.min(envelope.len() - 1);
            envelope[index] ^= 1;
        } else if matches!(data[cursor] % 6, 1) {
            let index = position.min(envelope.len());
            envelope.insert(index, 0);
        } else if matches!(data[cursor] % 6, 2) {
            envelope.truncate(envelope.len().saturating_sub(1));
        } else if matches!(data[cursor] % 6, 3) {
            let index = position.min(envelope.len() - 1);
            let inserted = envelope[index];
            envelope.insert(index, inserted ^ 0x80);
        } else if matches!(data[cursor] % 6, 4) {
            let index = position.min(envelope.len() - 1);
            let witness = (index + 7) % envelope.len();
            envelope.swap(index, witness);
        } else {
            envelope.reverse();
        }
        cursor += 4;
        edits += 1;
    }

    if envelope == seed {
        return;
    }

    // Digest-forge attempt: mutated bytes with the authentic digest pasted
    // back must not decode.
    let split_at = envelope.len().saturating_sub(32);
    let forged = [envelope[..split_at].to_vec(), seed_digest.clone()].concat();
    if let Ok(batch) = buffered_writes::SealedBatch::from_envelope_bytes(&forged) {
        panic!(
            "digest forge accepted: mutated envelope decoded with a pasted seed digest (batch id {:?})",
            batch.batch_id()
        );
    }

    // Round-trip the authentic seed: an Ok decode is identity-stable.
    let original = buffered_writes::SealedBatch::from_envelope_bytes(&seed)
        .expect("seed envelope decodes");
    let restored = buffered_writes::SealedBatch::from_envelope_bytes(
        original.to_envelope_bytes().unwrap().as_ref(),
    )
    .expect("seed round trip decodes");
    assert!(restored.verify_digest());
});

/// One authentic sealed envelope through the production writer so the fuzz
/// target owns a real digest (fixture path mirrors `envelopes.rs`).
fn sealed_envelope_bytes() -> Vec<u8> {
    let batch = run_once();
    batch
        .to_envelope_bytes()
        .expect("seed envelope encodes")
        .to_vec()
}

fn sealed_envelope_digest() -> Vec<u8> {
    run_once().digest().to_vec()
}

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
