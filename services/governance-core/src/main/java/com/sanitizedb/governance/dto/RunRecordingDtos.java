package com.sanitizedb.governance.dto;

import com.sanitizedb.governance.entity.AuditCertificate;
import com.sanitizedb.governance.entity.MaskingPolicy.ColumnRuleSpec;
import com.sanitizedb.governance.entity.SyncJob;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class RunRecordingDtos {

    private RunRecordingDtos() {}

    public record TableRunSummary(
        String qualifiedName,
        long rowsProcessed,
        long durationMs,
        boolean completed
    ) {}

    public record RecordSyncRunRequest(
        UUID jobId,
        String orgId,
        String policyId,
        String sourceConnectionId,
        String targetConnectionId,
        String status, // SUCCEEDED | FAILED | CANCELLED | BLOCKED_DRIFT
        String triggerSource,
        String triggeredBy,
        String workerNodeId,
        String engineVersion,
        String saltCommitmentSha256,
        long totalRowsMasked,
        long totalBytesStreamed,
        long durationMs,
        double avgRowsPerSec,
        boolean zeroDiskWritesVerified,
        boolean schemaDriftDetected,
        List<TableRunSummary> tables,
        String errorMessage,
        OffsetDateTime startedAt,
        OffsetDateTime completedAt
    ) {}

    public record SyncRunResponse(
        SyncJob syncJob,
        AuditCertificate certificate
    ) {}

    public record PolicyRulesUpdateRequest(
        Map<String, Map<String, ColumnRuleSpec>> rulesJson
    ) {}

    public record LiveColumnInfo(
        String name,
        String dataType,
        boolean isNullable,
        boolean isPrimaryKey,
        String detectedPii,
        double piiConfidence,
        String riskLevel,
        String matchedPattern,
        String detectionReason
    ) {}

    public record LiveTableInfo(
        String schemaName,
        String tableName,
        List<LiveColumnInfo> columns
    ) {}

    public record LiveSchemaPayload(
        String schemaFingerprintSha256,
        List<LiveTableInfo> tables
    ) {}

    public record UnmappedColumnDrift(
        String tableId,
        String schemaName,
        String tableName,
        String columnName,
        String dataType,
        String riskLevel,          // HIGH | MEDIUM | LOW
        String detectedPii,        // EMAIL | PHONE | NATIONAL_ID | CREDIT_CARD | STREET_ADDRESS | IP_ADDRESS | DATE_OF_BIRTH | FULL_NAME | NONE
        double piiConfidence,
        String matchedPattern,
        String reason,
        String suggestedStrategy,  // DETERMINISTIC_FAKE | PARTIAL_MASK | NULLIFY | SHUFFLE | PASS_THROUGH
        String suggestedDomain,
        int suggestedPreservePrefix,
        int suggestedPreserveSuffix
    ) {}

    public record PolicyDriftInspectionReport(
        UUID policyId,
        String policyName,
        int policyVersion,
        String schemaFingerprintSha256,
        boolean driftDetected,
        boolean strictDriftBlock,
        boolean syncBlocked,
        int highRiskCount,
        int mediumRiskCount,
        int lowRiskCount,
        List<UnmappedColumnDrift> unmappedColumns,
        List<LiveTableInfo> liveTables,
        OffsetDateTime inspectedAt
    ) {}
}
