#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CounterMetric {
    AnalyticsCompactionObjectsReadTotalMetric,
    AnalyticsCompactionObjectsWrittenTotalMetric,
    AnalyticsCompactionRunsTotalMetric,
    AnalyticsIngestionBytesWrittenTotalMetric,
    AnalyticsIngestionCursorStallsTotalMetric,
    AnalyticsIngestionFailuresTotalMetric,
    AnalyticsIngestionLeaseConflictsTotalMetric,
    AnalyticsIngestionLeaseErrorsTotalMetric,
    AnalyticsIngestionLeasesAcquiredTotalMetric,
    AnalyticsIngestionProcessErrorsTotalMetric,
    AnalyticsIngestionRecordsDedupedTotalMetric,
    AnalyticsIngestionRecordsDeletedTotalMetric,
    AnalyticsIngestionRecordsFetchedTotalMetric,
    AnalyticsIngestionRecordsInsertedTotalMetric,
    AnalyticsIngestionRecordsUniqueTotalMetric,
    AnalyticsIngestionRecordsUpdatedTotalMetric,
    AnalyticsIngestionSchemaChangesTotalMetric,
    AnalyticsIngestionTableErrorsTotalMetric,
    AnalyticsIngestionTablesTotalMetric,
    AnalyticsIngestionTransactionsTotalMetric,
    AnalyticsQueryRecordsReturnedTotalMetric,
    AuditEmitterEventsRecordedTotal,
    AuditEmitterWriteFailuresTotal,
    AuditEmitterWriteRetriesTotal,
    AuditEmitterWriteSuccessTotal,
    AuditTransactionalCowriteSuccessTotal,
    AuditTransactionalOverflowTotal,
    AuthzApiDecisionsTotal,
    AuthzCedarEvaluationErrorsTotal,
    AuthzApiTokenContextDenyTotal,
    AuthzApiTokenContextTotal,
    AuthzAxumDecisionTotal,
    AuthzAxumErrorTotal,
    AuthzJwtVerifyTotal,
    AuthzProjectionOperationsTotal,
    AuthzTokenContextDenyTotal,
    BackfillJobExpiredLockFoundCount,
    BackfillJobIdleCount,
    BackfillJobsThrottledCount,
    BillingRouteMetricCandidatesTotal,
    BillingOperationUsageDuplicateRequestsTotal,
    BillingRoutePolicyApiOperationTotal,
    BgJobsLockSkipsTotalMetric,
    BgJobsRunErrorsTotalMetric,
    BgJobsRunsTotalMetric,
    BgWorkerItemsProcessedTotalMetric,
    BgWorkerLeaseConflictsTotalMetric,
    BgWorkerProcessErrorsTotalMetric,
    BgWorkerRunErrorsTotalMetric,
    CustomDomainBillingTransitionsTotalMetric,
    CustomDomainFrontDoorAttemptsTotalMetric,
    CustomDomainFrontDoorOutcomesTotalMetric,
    CustomDomainReconcileAttemptsTotalMetric,
    CustomDomainReconcileOutcomesTotalMetric,
    FoundationdbOperationBytesTotal,
    FoundationdbOperationsTotal,
    GsiUpdateEmptyBatches,
    GsiUpdateOps,
    GsiUpdatePointerBatches,
    GsiUpdateStreamItems,
    HttpRequestBytesTotalMetric,
    HttpResponseBytesTotalMetric,
    MetricAuthnAuthenticationAttemptTotal,
    MetricAuthnAuthenticatorDisabledTotal,
    MetricAuthnAuthenticatorLifecycleTotal,
    MetricAuthnFraudReportTotal,
    MetricAuthnRecoveryAttemptTotal,
    MetricAuthnSessionAssuranceTotal,
    MetricAuthnSupportInterventionTotal,
    MetricBlocklistBatchWriteRetryExhaustedTotal,
    MetricBlocklistBatchWriteRetryTotal,
    MetricFederatedProvisionHookTotal,
    MetricFederatedProvisionPolicyTotal,
    MetricFederatedProvisionStageTotal,
    MetricFederatedProvisionTotal,
    MetricHttpRequestAttempts,
    MetricHttpRequestErrors,
    MetricHttpRequestRetries,
    LimitsExpiryReclaimedTotal,
    LimitsExpiryRowsScannedTotal,
    LimitsExpirySweepsTotal,
    LimitsTransitionConflictsTotal,
    LimitsTransitionTotal,
    MetricNotificationsDeliveryAttemptTotal,
    MetricNotificationsDeliveryBackpressureTotal,
    MetricNotificationsDeliveryEnqueuedTotal,
    MetricNotificationsDeliveryFailedTotal,
    MetricNotificationsDeliveryRetryScheduledTotal,
    MetricNotificationsDeliverySuccessTotal,
    MetricNotificationsDestinationCircuitOpenTotal,
    MetricNotificationsQueuePointerEnqueuedTotal,
    MetricNotificationsQueuePointerProcessTotal,
    MetricNotificationsWorkerProcessedTotal,
    MetricNotificationsWorkerRunTotal,
    MetricOauthUserinfoFallbackTotal,
    MetricQueueEmptyReceivesTotal,
    MetricOutboxItemsProcessedTotal,
    ManagedTenantDecisionsTotal,
    ManagedTenantQuotaDenialsTotal,
    ManagedTenantSupportSessionTransitionsTotal,
    ManagedTenantSuspensionsTotal,
    ManagedTenantTemplateApplyTotal,
    PrefetchBatchGetTotal,
    PrefetchFallbackGetTotal,
    PrefetchKeysTotal,
    PrefetchSkippedHotTotal,
    PrefetchUnprocessedTotal,
    PartitionLoadSamplesFlushedTotalMetric,
    PartitionReconcileActionsTotalMetric,
    PartitionReconcileRunsTotalMetric,
    PartitionRoutingRetriesTotalMetric,
    MetricSamlAcsIssuerOrgResolutionTotal,
    MetricSamlProviderMetadataTotal,
    MetricSamlProviderSsoFailureTotal,
    MetricSecurityFailureTotal,
    MetricSloSuccessTotal,
    MetricSsoSuccessTotal,
    MetricStaleCleanupTotal,
    RemoteStorageFailoverCount,
    RemoteStorageRequestBytesTotalMetric,
    RemoteStorageResponseBytesTotalMetric,
    RocksdbConditionalPutFailureMetric,
    RocksdbConditionalPutRetryMetric,
    SamlProviderApiErrorTotal,
    StorageBilledItemOpsTotalMetric,
    StorageLogicalItemBytesTotalMetric,
    StorageDdbBatchGetItemCacheHitMetric,
    StorageDdbBatchGetItemCacheHitPartialMetric,
    StorageDdbBatchGetItemCacheMissMetric,
    StorageDdbGetItemCacheHitMetric,
    StorageDdbGetItemCacheMissMetric,
    StorageDdbAuthoritativePreimageHitMetric,
    StorageDdbAuthoritativePreimageMissMetric,
    StorageDdbGuardConflictFallbackMetric,
    StorageDdbGuardUnsupportedFallbackMetric,
    StorageMultiRegionApplyTotalMetric,
    StorageMultiRegionAuthFailureTotalMetric,
    StorageMultiRegionConflictTotalMetric,
    StorageApiDynamodbRequestsTotalMetric,
    StorageApiDynamodbRequestLatencyMicrosTotalMetric,
    StorageApiDynamodbStageTotalMetric,
    StorageProviderStageTotalMetric,
    StorageOperationTotalMetric,
    StorageDdbQueryCacheHitMetric,
    StorageDdbQueryCacheHitPartialMetric,
    StorageDdbQueryCacheMissMetric,
    StreamTrimDecodeFailures,
    StreamTrimDeleteBatches,
    StreamTrimGroupsDeleted,
    StreamTrimGroupsProtectedByReplication,
    StreamTrimItemsScanned,
    StreamTrimPagesScanned,
    StreamTtlCleanupItemsDeletedTotalMetric,
    StreamTtlCleanupRunsTotalMetric,
    StreamTtlCleanupStreamsScannedTotalMetric,
    TtlSweepExpiredLockFoundCount,
    TtlSweepItemsDeleted,
    TtlSweepRetryAttempts,
    TtlSweepRetryBatches,
    TtlSweepRetryFailures,
    TtlSweepShardsChecked,
    TtlSweepTablesChecked,
    TtlSweepThrottledCount,
    VaultTokenRenewalMetricAttemptTotal,
    VaultTokenRenewalMetricFailureTotal,
    VaultTokenRenewalMetricFatalTotal,
    VaultTokenRenewalMetricLockAcquiredTotal,
    VaultTokenRenewalMetricLockConflictTotal,
    VaultTokenRenewalMetricNotRenewableTotal,
    VaultTokenRenewalMetricSuccessTotal,
    VaultTokenRenewalMetricVerifyFailedTotal,
    CacheClusterJoinTotal,
    CacheClusterLeaveTotal,
    CacheClusterReconfigureTotal,
    CacheClusterElectionTotal,
    CacheClusterMigrationTotal,
}

impl CounterMetric {
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AnalyticsCompactionObjectsReadTotalMetric => {
                "analytics_compaction_objects_read_total"
            }
            Self::AnalyticsCompactionObjectsWrittenTotalMetric => {
                "analytics_compaction_objects_written_total"
            }
            Self::AnalyticsCompactionRunsTotalMetric => "analytics_compaction_runs_total",
            Self::AnalyticsIngestionBytesWrittenTotalMetric => {
                "analytics_ingestion_bytes_written_total"
            }
            Self::AnalyticsIngestionCursorStallsTotalMetric => {
                "analytics_ingestion_cursor_stalls_total"
            }
            Self::AnalyticsIngestionFailuresTotalMetric => "analytics_ingestion_failures_total",
            Self::AnalyticsIngestionLeaseConflictsTotalMetric => {
                "analytics_ingestion_lease_conflicts_total"
            }
            Self::AnalyticsIngestionLeaseErrorsTotalMetric => {
                "analytics_ingestion_lease_errors_total"
            }
            Self::AnalyticsIngestionLeasesAcquiredTotalMetric => {
                "analytics_ingestion_leases_acquired_total"
            }
            Self::AnalyticsIngestionProcessErrorsTotalMetric => {
                "analytics_ingestion_process_errors_total"
            }
            Self::AnalyticsIngestionRecordsDedupedTotalMetric => {
                "analytics_ingestion_records_deduped_total"
            }
            Self::AnalyticsIngestionRecordsDeletedTotalMetric => {
                "analytics_ingestion_records_deleted_total"
            }
            Self::AnalyticsIngestionRecordsFetchedTotalMetric => {
                "analytics_ingestion_records_fetched_total"
            }
            Self::AnalyticsIngestionRecordsInsertedTotalMetric => {
                "analytics_ingestion_records_inserted_total"
            }
            Self::AnalyticsIngestionRecordsUniqueTotalMetric => {
                "analytics_ingestion_records_unique_total"
            }
            Self::AnalyticsIngestionRecordsUpdatedTotalMetric => {
                "analytics_ingestion_records_updated_total"
            }
            Self::AnalyticsIngestionSchemaChangesTotalMetric => {
                "analytics_ingestion_schema_changes_total"
            }
            Self::AnalyticsIngestionTableErrorsTotalMetric => {
                "analytics_ingestion_table_errors_total"
            }
            Self::AnalyticsIngestionTablesTotalMetric => "analytics_ingestion_tables_total",
            Self::AnalyticsIngestionTransactionsTotalMetric => {
                "analytics_ingestion_transactions_total"
            }
            Self::AnalyticsQueryRecordsReturnedTotalMetric => {
                "analytics_query_records_returned_total"
            }
            Self::AuditEmitterEventsRecordedTotal => "audit_emitter_events_recorded_total",
            Self::AuditEmitterWriteFailuresTotal => "audit_emitter_write_failures_total",
            Self::AuditEmitterWriteRetriesTotal => "audit_emitter_write_retries_total",
            Self::AuditEmitterWriteSuccessTotal => "audit_emitter_write_success_total",
            Self::AuditTransactionalCowriteSuccessTotal => {
                "audit_transactional_cowrite_success_total"
            }
            Self::AuditTransactionalOverflowTotal => "audit_transactional_overflow_total",
            Self::AuthzApiDecisionsTotal => "authz.api.decisions_total",
            Self::AuthzCedarEvaluationErrorsTotal => "authz.cedar.evaluation_errors_total",
            Self::AuthzApiTokenContextDenyTotal => "authz.api.token_context_deny_total",
            Self::AuthzApiTokenContextTotal => "authz.api.token_context_total",
            Self::AuthzAxumDecisionTotal => "authz.axum.decision_total",
            Self::AuthzAxumErrorTotal => "authz.axum.error_total",
            Self::AuthzJwtVerifyTotal => "authz.jwt.verify_total",
            Self::AuthzProjectionOperationsTotal => "authz.projection.operations_total",
            Self::AuthzTokenContextDenyTotal => "authz.token_context_deny_total",
            Self::BackfillJobExpiredLockFoundCount => "backfill.job.expired.lock.found.count",
            Self::BackfillJobIdleCount => "backfill.job.idle.count",
            Self::BackfillJobsThrottledCount => "backfill.jobs.throttled.count",
            Self::BillingRouteMetricCandidatesTotal => "billing_route_metric_candidates_total",
            Self::BillingOperationUsageDuplicateRequestsTotal => {
                "billing_operation_usage_duplicate_requests_total"
            }
            Self::BillingRoutePolicyApiOperationTotal => "api_operation",

            Self::BgJobsLockSkipsTotalMetric => "bg.jobs.lock.skips.total",
            Self::BgJobsRunErrorsTotalMetric => "bg.jobs.run.errors.total",
            Self::BgJobsRunsTotalMetric => "bg.jobs.runs.total",
            Self::BgWorkerItemsProcessedTotalMetric => "bg.worker.items.processed.total",
            Self::BgWorkerLeaseConflictsTotalMetric => "bg.worker.lease.conflicts.total",
            Self::BgWorkerProcessErrorsTotalMetric => "bg.worker.process.errors.total",
            Self::BgWorkerRunErrorsTotalMetric => "bg.worker.run.errors.total",
            Self::CustomDomainBillingTransitionsTotalMetric => {
                "custom_domain_billing_transitions_total"
            }
            Self::CustomDomainFrontDoorAttemptsTotalMetric => {
                "custom_domain_front_door_attempts_total"
            }
            Self::CustomDomainFrontDoorOutcomesTotalMetric => {
                "custom_domain_front_door_outcomes_total"
            }
            Self::CustomDomainReconcileAttemptsTotalMetric => {
                "custom_domain_reconcile_attempts_total"
            }
            Self::CustomDomainReconcileOutcomesTotalMetric => {
                "custom_domain_reconcile_outcomes_total"
            }
            Self::FoundationdbOperationBytesTotal => "foundationdb_operation_bytes_total",
            Self::FoundationdbOperationsTotal => "foundationdb_operations_total",

            Self::GsiUpdateEmptyBatches => "gsi.update.empty.batches",
            Self::GsiUpdateOps => "gsi.update.ops",
            Self::GsiUpdatePointerBatches => "gsi.update.pointer.batches",
            Self::GsiUpdateStreamItems => "gsi.update.stream.items",
            Self::HttpRequestBytesTotalMetric => "http.request.bytes.total",
            Self::HttpResponseBytesTotalMetric => "http.response.bytes.total",
            Self::MetricAuthnAuthenticationAttemptTotal => "authn.authentication_attempt_total",
            Self::MetricAuthnAuthenticatorDisabledTotal => "authn.authenticator_disabled_total",
            Self::MetricAuthnAuthenticatorLifecycleTotal => "authn.authenticator_lifecycle_total",
            Self::MetricAuthnFraudReportTotal => "authn.fraud_report_total",
            Self::MetricAuthnRecoveryAttemptTotal => "authn.recovery_attempt_total",
            Self::MetricAuthnSessionAssuranceTotal => "authn.session_assurance_total",
            Self::MetricAuthnSupportInterventionTotal => "authn.support_intervention_total",
            Self::MetricBlocklistBatchWriteRetryExhaustedTotal => {
                "blocklist.batch_write_retry_exhausted_total"
            }
            Self::MetricBlocklistBatchWriteRetryTotal => "blocklist.batch_write_retry_total",
            Self::MetricFederatedProvisionHookTotal => "authn.federated.provision_hook_total",
            Self::MetricFederatedProvisionPolicyTotal => "authn.federated.provision_policy_total",
            Self::MetricFederatedProvisionStageTotal => "authn.federated.provision_stage_total",
            Self::MetricFederatedProvisionTotal => "authn.federated.provision_total",
            Self::MetricHttpRequestAttempts => "http.request.attempts",
            Self::MetricHttpRequestErrors => "http.request.errors",
            Self::MetricHttpRequestRetries => "http.request.retries",
            Self::LimitsExpiryReclaimedTotal => "limits.expiry.reclaimed.total",
            Self::LimitsExpiryRowsScannedTotal => "limits.expiry.rows.scanned.total",
            Self::LimitsExpirySweepsTotal => "limits.expiry.sweeps.total",
            Self::LimitsTransitionConflictsTotal => "limits.transition.conflicts.total",
            Self::LimitsTransitionTotal => "limits.transition.total",
            Self::MetricNotificationsDeliveryAttemptTotal => "notifications_delivery_attempt_total",
            Self::MetricNotificationsDeliveryBackpressureTotal => {
                "notifications_delivery_backpressure_total"
            }
            Self::MetricNotificationsDeliveryEnqueuedTotal => {
                "notifications_delivery_enqueued_total"
            }
            Self::MetricNotificationsDeliveryFailedTotal => "notifications_delivery_failed_total",
            Self::MetricNotificationsDeliveryRetryScheduledTotal => {
                "notifications_delivery_retry_scheduled_total"
            }
            Self::MetricNotificationsDeliverySuccessTotal => "notifications_delivery_success_total",
            Self::MetricNotificationsDestinationCircuitOpenTotal => {
                "notifications_destination_circuit_open_total"
            }
            Self::MetricNotificationsQueuePointerEnqueuedTotal => {
                "notifications_queue_pointer_enqueued_total"
            }
            Self::MetricNotificationsQueuePointerProcessTotal => {
                "notifications_queue_pointer_process_total"
            }
            Self::MetricNotificationsWorkerProcessedTotal => "notifications_worker_processed_total",
            Self::MetricNotificationsWorkerRunTotal => "notifications_worker_run_total",
            Self::MetricOauthUserinfoFallbackTotal => "authn.oauth.userinfo_fallback_total",
            Self::MetricQueueEmptyReceivesTotal => "jobs.immediate.empty.receives.total",
            Self::MetricOutboxItemsProcessedTotal => "jobs.immediate.outbox.items.processed.total",
            Self::ManagedTenantDecisionsTotal => "managed_tenant_decisions_total",
            Self::ManagedTenantQuotaDenialsTotal => "managed_tenant_quota_denials_total",
            Self::ManagedTenantSupportSessionTransitionsTotal => {
                "managed_tenant_support_session_transitions_total"
            }
            Self::ManagedTenantSuspensionsTotal => "managed_tenant_suspensions_total",
            Self::ManagedTenantTemplateApplyTotal => "managed_tenant_template_apply_total",
            Self::PrefetchBatchGetTotal => "prefetch.batch.get.total",
            Self::PrefetchFallbackGetTotal => "prefetch.fallback.get.total",
            Self::PrefetchKeysTotal => "prefetch.keys.total",
            Self::PrefetchSkippedHotTotal => "prefetch.skipped.hot.total",
            Self::PrefetchUnprocessedTotal => "prefetch.unprocessed.total",
            Self::PartitionLoadSamplesFlushedTotalMetric => "partition.load.samples.flushed.total",
            Self::PartitionReconcileActionsTotalMetric => "partition.reconcile.actions.total",
            Self::PartitionReconcileRunsTotalMetric => "partition.reconcile.runs.total",
            Self::PartitionRoutingRetriesTotalMetric => "partition.routing.retries.total",
            Self::MetricSamlAcsIssuerOrgResolutionTotal => {
                "authn.saml.acs.issuer_org_resolution_total"
            }
            Self::MetricSamlProviderMetadataTotal => "saml_provider_metadata_total",
            Self::MetricSamlProviderSsoFailureTotal => "saml_provider_sso_failure_total",
            Self::MetricSecurityFailureTotal => "saml_provider_security_failure_total",
            Self::MetricSloSuccessTotal => "saml_provider_slo_success_total",
            Self::MetricSsoSuccessTotal => "saml_provider_sso_success_total",
            Self::MetricStaleCleanupTotal => "saml_provider_stale_cleanup_total",
            Self::RemoteStorageFailoverCount => "remote.storage.failover.count",
            Self::RemoteStorageRequestBytesTotalMetric => "remote.storage.request.bytes.total",
            Self::RemoteStorageResponseBytesTotalMetric => "remote.storage.response.bytes.total",
            Self::RocksdbConditionalPutFailureMetric => "kv.rocksdb.conditional.put.failure.total",
            Self::RocksdbConditionalPutRetryMetric => "kv.rocksdb.conditional.put.retry.total",
            Self::SamlProviderApiErrorTotal => "saml_provider_api_error_total",
            Self::StorageBilledItemOpsTotalMetric => "storage.billed.item.ops.total",
            Self::StorageLogicalItemBytesTotalMetric => "storage.logical.item.bytes.total",
            Self::StorageDdbBatchGetItemCacheHitMetric => "ddb.batch.get.item.cache.hit",
            Self::StorageDdbBatchGetItemCacheHitPartialMetric => {
                "ddb.batch.get.item.cache.hit.partial"
            }
            Self::StorageDdbBatchGetItemCacheMissMetric => "ddb.batch.get.item.cache.miss",
            Self::StorageDdbGetItemCacheHitMetric => "ddb.get.item.cache.hit",
            Self::StorageDdbGetItemCacheMissMetric => "ddb.get.item.cache.miss",
            Self::StorageDdbAuthoritativePreimageHitMetric => "ddb.authoritative.preimage.hit",
            Self::StorageDdbAuthoritativePreimageMissMetric => "ddb.authoritative.preimage.miss",
            Self::StorageDdbGuardConflictFallbackMetric => "ddb.guard.conflict.fallback",
            Self::StorageDdbGuardUnsupportedFallbackMetric => "ddb.guard.unsupported.fallback",
            Self::StorageMultiRegionApplyTotalMetric => "storage.multi.region.apply.total",
            Self::StorageMultiRegionAuthFailureTotalMetric => {
                "storage.multi.region.auth.failure.total"
            }
            Self::StorageMultiRegionConflictTotalMetric => "storage.multi.region.conflict.total",
            Self::StorageApiDynamodbRequestsTotalMetric => "storage.api.dynamodb.requests.total",
            Self::StorageApiDynamodbRequestLatencyMicrosTotalMetric => {
                "storage.api.dynamodb.request.latency.micros.total"
            }
            Self::StorageApiDynamodbStageTotalMetric => "storage.api.dynamodb.stage.total",
            Self::StorageProviderStageTotalMetric => "storage.provider.stage.total",
            Self::StorageOperationTotalMetric => "storage.operation.total",
            Self::StorageDdbQueryCacheHitMetric => "ddb.query.cache.hit",
            Self::StorageDdbQueryCacheHitPartialMetric => "ddb.query.cache.hit.partial",
            Self::StorageDdbQueryCacheMissMetric => "ddb.query.cache.miss",
            Self::StreamTrimDecodeFailures => "stream.trim.decode.failures",
            Self::StreamTrimDeleteBatches => "stream.trim.delete.batches",
            Self::StreamTrimGroupsDeleted => "stream.trim.groups.deleted",
            Self::StreamTrimGroupsProtectedByReplication => {
                "stream.trim.groups.protected.by.replication"
            }
            Self::StreamTrimItemsScanned => "stream.trim.items.scanned",
            Self::StreamTrimPagesScanned => "stream.trim.pages.scanned",
            Self::StreamTtlCleanupItemsDeletedTotalMetric => {
                "stream.ttl.cleanup.items.deleted.total"
            }
            Self::StreamTtlCleanupRunsTotalMetric => "stream.ttl.cleanup.runs.total",
            Self::StreamTtlCleanupStreamsScannedTotalMetric => {
                "stream.ttl.cleanup.streams.scanned.total"
            }
            Self::TtlSweepExpiredLockFoundCount => "ttl.sweep.expired.lock.found.count",
            Self::TtlSweepItemsDeleted => "ttl.sweep.items.deleted",
            Self::TtlSweepRetryAttempts => "ttl.sweep.retry.attempts",
            Self::TtlSweepRetryBatches => "ttl.sweep.retry.batches",
            Self::TtlSweepRetryFailures => "ttl.sweep.retry.failures",
            Self::TtlSweepShardsChecked => "ttl.sweep.shards.checked",
            Self::TtlSweepTablesChecked => "ttl.sweep.tables.checked",
            Self::TtlSweepThrottledCount => "ttl.sweep.throttled.count",
            Self::VaultTokenRenewalMetricAttemptTotal => "vault_token_renewal_attempt_total",
            Self::VaultTokenRenewalMetricFailureTotal => "vault_token_renewal_failure_total",
            Self::VaultTokenRenewalMetricFatalTotal => "vault_token_renewal_fatal_total",
            Self::VaultTokenRenewalMetricLockAcquiredTotal => {
                "vault_token_renewal_lock_acquired_total"
            }
            Self::VaultTokenRenewalMetricLockConflictTotal => {
                "vault_token_renewal_lock_conflict_total"
            }
            Self::VaultTokenRenewalMetricNotRenewableTotal => {
                "vault_token_renewal_not_renewable_total"
            }
            Self::VaultTokenRenewalMetricSuccessTotal => "vault_token_renewal_success_total",
            Self::VaultTokenRenewalMetricVerifyFailedTotal => {
                "vault_token_renewal_verify_failed_total"
            }
            Self::CacheClusterJoinTotal => "cache.cluster.join.total",
            Self::CacheClusterLeaveTotal => "cache.cluster.leave.total",
            Self::CacheClusterReconfigureTotal => "cache.cluster.reconfigure.total",
            Self::CacheClusterElectionTotal => "cache.cluster.election.total",
            Self::CacheClusterMigrationTotal => "cache.cluster.migration.total",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GaugeMetric {
    AnalyticsIngestionQueueDepthMetric,
    BackfillJobsConcurrentCount,
    BgJobsRunningCountMetric,
    CustomDomainActivationStateTotalMetric,
    CustomDomainBillingStateTotalMetric,
    CustomDomainCertificateStateTotalMetric,
    CustomDomainFrontDoorStateTotalMetric,
    CustomDomainProviderTotalMetric,
    CustomDomainValidationStateTotalMetric,
    MetricOutboxMaxDelayMs,
    MetricNotificationsWorkerDueBatchSize,
    MetricNotificationsWorkerOldestDueAgeMs,
    MetricFederatedProvisionEnabledSources,
    PartitionFamilyHotFamiliesMetric,
    PartitionFamilyManagedFamiliesMetric,
    PartitionFamilyOpenPartitionsMetric,
    PartitionFamilyPressureMetric,
    PartitionFamilyTransitionPartitionsMetric,
    StorageMultiRegionHeartbeatStalenessMsMetric,
    StorageMultiRegionReplicationLagMsMetric,
    StorageMultiRegionSenderQueueDepthMetric,
    StorageDdbCacheHitRatioMetric,
    CacheClusterActiveNodes,
    CacheClusterActiveShards,
}

impl GaugeMetric {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AnalyticsIngestionQueueDepthMetric => "analytics_ingestion_queue_depth",
            Self::BackfillJobsConcurrentCount => "backfill.jobs.concurrent.count",
            Self::BgJobsRunningCountMetric => "bg.jobs.running.count",
            Self::CustomDomainActivationStateTotalMetric => "custom_domain_activation_state_total",
            Self::CustomDomainBillingStateTotalMetric => "custom_domain_billing_state_total",
            Self::CustomDomainCertificateStateTotalMetric => {
                "custom_domain_certificate_state_total"
            }
            Self::CustomDomainFrontDoorStateTotalMetric => "custom_domain_front_door_state_total",
            Self::CustomDomainProviderTotalMetric => "custom_domain_provider_total",
            Self::CustomDomainValidationStateTotalMetric => "custom_domain_validation_state_total",
            Self::MetricOutboxMaxDelayMs => "jobs.immediate.outbox.max.delay.ms",
            Self::MetricNotificationsWorkerDueBatchSize => "notifications_worker_due_batch_size",
            Self::MetricNotificationsWorkerOldestDueAgeMs => {
                "notifications_worker_oldest_due_age_ms"
            }
            Self::MetricFederatedProvisionEnabledSources => {
                "authn.federated.provision_enabled_sources"
            }
            Self::PartitionFamilyHotFamiliesMetric => "partition.family.hot.families",
            Self::PartitionFamilyManagedFamiliesMetric => "partition.family.managed.families",
            Self::PartitionFamilyOpenPartitionsMetric => "partition.family.open.partitions",
            Self::PartitionFamilyPressureMetric => "partition.family.pressure",
            Self::PartitionFamilyTransitionPartitionsMetric => {
                "partition.family.transition.partitions"
            }
            Self::StorageMultiRegionHeartbeatStalenessMsMetric => {
                "storage.multi.region.heartbeat.staleness.ms"
            }
            Self::StorageMultiRegionReplicationLagMsMetric => {
                "storage.multi.region.replication.lag.ms"
            }
            Self::StorageMultiRegionSenderQueueDepthMetric => {
                "storage.multi.region.sender.queue.depth"
            }
            Self::StorageDdbCacheHitRatioMetric => "ddb.cache.hit.ratio",
            Self::CacheClusterActiveNodes => "cache.cluster.active.nodes",
            Self::CacheClusterActiveShards => "cache.cluster.active.shards",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HistogramMetric {
    AnalyticsCompactionRuntimeMsMetric,
    AnalyticsIngestionTableRuntimeMsMetric,
    AnalyticsQueryRuntimeMsMetric,
    AuthzApiLatencyMs,
    AuthzAxumDecisionMs,
    AuthzJwtVerifyMs,
    BackfillEnumerateLatencyMs,
    BackfillJobRuntimeMs,
    BackfillLockAcquireLatencyMs,
    BgJobsRunDurationMsMetric,
    BgWorkerRunOnceMsMetric,
    BillingOperationUsageIngestionLagMs,
    FoundationdbGetReadVersionLatencyMs,
    GsiUpdateRuntimeMs,
    MetricAuthnFraudResolutionMs,
    MetricAuthnLockoutDurationMs,
    MetricFederatedProvisionHookLatencyMs,
    MetricFederatedProvisionLatencyMs,
    MetricFederatedProvisionStageLatencyMs,
    LimitsExpirySweepDurationMs,
    LimitsTransitionDurationMs,
    MetricHttpRequestLatencyMs,
    MetricOauthUserinfoFallbackLatencyMs,
    MetricQueueMessageDelayMs,
    MetricSamlAcsIssuerOrgResolutionLatencyMs,
    PartitionReconcileRuntimeMsMetric,
    RemoteStorageRequestLatencyMs,
    RequestLatencyMetric,
    StorageApiDynamodbRequestLatencyMsMetric,
    StorageApiDynamodbStageLatencyMsMetric,
    StorageProviderStageLatencyMsMetric,
    StorageMultiRegionHeartbeatRttMsMetric,
    StorageOperationLatencyMsMetric,
    StreamTrimRuntimeMs,
    StreamTtlCleanupRuntimeMsMetric,
    TtlSweepRuntimeMs,
}

impl HistogramMetric {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AnalyticsCompactionRuntimeMsMetric => "analytics_compaction_runtime_ms",
            Self::AnalyticsIngestionTableRuntimeMsMetric => "analytics_ingestion_table_runtime_ms",
            Self::AnalyticsQueryRuntimeMsMetric => "analytics_query_runtime_ms",
            Self::AuthzApiLatencyMs => "authz.api.latency_ms",
            Self::AuthzAxumDecisionMs => "authz.axum.decision_ms",
            Self::AuthzJwtVerifyMs => "authz.jwt.verify_ms",
            Self::BackfillEnumerateLatencyMs => "backfill.enumerate.latency.ms",
            Self::BackfillJobRuntimeMs => "backfill.job.runtime.ms",
            Self::BackfillLockAcquireLatencyMs => "backfill.lock.acquire.latency.ms",
            Self::BgJobsRunDurationMsMetric => "bg.jobs.run.duration.ms",
            Self::BgWorkerRunOnceMsMetric => "bg.worker.run.once.ms",
            Self::BillingOperationUsageIngestionLagMs => "billing_operation_usage_ingestion_lag_ms",
            Self::FoundationdbGetReadVersionLatencyMs => "foundationdb.get.read.version.latency.ms",
            Self::GsiUpdateRuntimeMs => "gsi.update.runtime.ms",
            Self::MetricAuthnFraudResolutionMs => "authn.fraud_resolution_ms",
            Self::MetricAuthnLockoutDurationMs => "authn.lockout_duration_ms",
            Self::MetricFederatedProvisionHookLatencyMs => {
                "authn.federated.provision_hook_latency_ms"
            }
            Self::MetricFederatedProvisionLatencyMs => "authn.federated.provision_latency_ms",
            Self::MetricFederatedProvisionStageLatencyMs => {
                "authn.federated.provision_stage_latency_ms"
            }
            Self::LimitsExpirySweepDurationMs => "limits.expiry.sweep.duration.ms",
            Self::LimitsTransitionDurationMs => "limits.transition.duration.ms",
            Self::MetricHttpRequestLatencyMs | Self::RequestLatencyMetric => {
                "http.request.latency.ms"
            }
            Self::MetricOauthUserinfoFallbackLatencyMs => {
                "authn.oauth.userinfo_fallback_latency_ms"
            }
            Self::MetricQueueMessageDelayMs => "jobs.immediate.queue.message.delay.ms",
            Self::MetricSamlAcsIssuerOrgResolutionLatencyMs => {
                "authn.saml.acs.issuer_org_resolution_latency_ms"
            }
            Self::PartitionReconcileRuntimeMsMetric => "partition.reconcile.runtime.ms",
            Self::RemoteStorageRequestLatencyMs => "remote.storage.request.latency.ms",
            Self::StorageApiDynamodbRequestLatencyMsMetric => {
                "storage.api.dynamodb.request.latency.ms"
            }
            Self::StorageApiDynamodbStageLatencyMsMetric => "storage.api.dynamodb.stage.latency.ms",
            Self::StorageProviderStageLatencyMsMetric => "storage.provider.stage.latency.ms",
            Self::StorageMultiRegionHeartbeatRttMsMetric => "storage.multi.region.heartbeat.rtt.ms",
            Self::StorageOperationLatencyMsMetric => "storage.operation.latency.ms",
            Self::StreamTrimRuntimeMs => "stream.trim.runtime.ms",
            Self::StreamTtlCleanupRuntimeMsMetric => "stream.ttl.cleanup.runtime.ms",
            Self::TtlSweepRuntimeMs => "ttl.sweep.runtime.ms",
        }
    }
}
