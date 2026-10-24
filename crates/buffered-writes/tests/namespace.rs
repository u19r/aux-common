use std::time::Duration;

use buffered_writes::{
    AtomicSink, BufferedWrites, Deadline, MemoryBuffer, OperationId, SinkError, SinkLimits,
    TenantScope, WriteAttempt, WriteOptions,
};

fn sink() -> AtomicSink<u32> {
    AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap()
}

#[tokio::test]
async fn given_retained_explicit_scope_when_another_namespace_attaches_then_reject_before_admission()
 {
    let buffer = MemoryBuffer::new(buffered_writes::Namespace::try_from("owner/v1").unwrap());
    let original = BufferedWrites::builder("owner/v1", sink())
        .with_buffer_provider(buffer.clone())
        .build()
        .unwrap();
    let options = WriteOptions::new()
        .with_scope(TenantScope::try_from("shared-tenant").unwrap())
        .with_operation_id(OperationId::generate_v7());
    original
        .add_write_item_with_options(7, options.clone())
        .await
        .unwrap();
    let other = BufferedWrites::builder("other/v1", sink())
        .with_buffer_provider(buffer)
        .build();
    assert!(
        other.is_err(),
        "another namespace attached to retained writes"
    );
    assert_eq!(original.flush_writes().await.items_settled, 1);
    original
        .add_write_item_with_options(7, options)
        .await
        .unwrap();
    assert!(
        original
            .shutdown(Deadline::after(Duration::from_secs(1)))
            .await
            .is_clean()
    );
}

#[cfg(feature = "disk")]
#[tokio::test]
async fn given_open_disk_records_when_another_namespace_reopens_then_reject_without_rewriting() {
    use buffered_writes::{ConfigurationError, DiskBuffer, Namespace};
    let directory = std::env::temp_dir().join(format!(
        "buffered-writes-namespace-{}",
        uuid::Uuid::now_v7()
    ));
    let owner = Namespace::try_from("owner/v1").unwrap();
    {
        let buffer = DiskBuffer::open(owner.clone(), &directory).unwrap();
        let writer = BufferedWrites::builder("owner/v1", sink())
            .with_buffer_provider(buffer)
            .build()
            .unwrap();
        writer.add_write_item(7).await.unwrap();
    }
    let path = directory.join("journal.bin");
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        DiskBuffer::open(Namespace::try_from("other/v1").unwrap(), &directory),
        Err(ConfigurationError::NamespaceMismatch)
    ));
    assert_eq!(std::fs::read(path).unwrap(), before);
    {
        let buffer = DiskBuffer::open(owner, &directory).unwrap();
        let writer = BufferedWrites::builder("owner/v1", sink())
            .with_buffer_provider(buffer)
            .build()
            .unwrap();
        assert_eq!(writer.flush_writes().await.items_settled, 1);
        assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(feature = "valkey")]
#[test]
fn given_configured_remote_provider_when_another_namespace_attaches_then_reject_without_network_io()
{
    use buffered_writes::{ConfigurationError, Namespace, ValkeyBuffer, ValkeyCredentials};
    let buffer = ValkeyBuffer::try_new(
        Namespace::try_from("owner/v1").unwrap(),
        "redis://127.0.0.1:1/",
        ValkeyCredentials::new("unused").with_tls_required(false),
    )
    .unwrap();
    assert!(matches!(
        BufferedWrites::builder("other/v1", sink())
            .with_buffer_provider(buffer)
            .build(),
        Err(ConfigurationError::NamespaceMismatch)
    ));
}
