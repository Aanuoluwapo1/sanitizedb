package com.sanitizedb.governance.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.ColumnTransformer;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "sync_jobs")
public class SyncJob {

    public enum JobStatus {
        QUEUED, VALIDATING, RUNNING, SUCCEEDED, FAILED, CANCELLED, BLOCKED_DRIFT
    }

    @Id
    private UUID id;

    @Column(name = "org_id", nullable = false)
    private UUID orgId;

    @Column(name = "policy_id", nullable = false)
    private UUID policyId;

    @Column(name = "source_connection_id", nullable = false)
    private UUID sourceConnectionId;

    @Column(name = "target_connection_id", nullable = false)
    private UUID targetConnectionId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @ColumnTransformer(write = "?::job_status")
    private JobStatus status = JobStatus.QUEUED;

    @Column(name = "trigger_source", nullable = false, length = 32)
    private String triggerSource = "CLI_CI";

    @Column(name = "triggered_by", nullable = false)
    private String triggeredBy = "orchestrator";

    @Column(name = "worker_node_id", length = 128)
    private String workerNodeId;

    @Column(name = "salt_commitment_sha256", nullable = false, length = 64)
    private String saltCommitmentSha256;

    @Column(name = "total_tables", nullable = false)
    private int totalTables;

    @Column(name = "completed_tables", nullable = false)
    private int completedTables;

    @Column(name = "rows_processed", nullable = false)
    private long rowsProcessed;

    @Column(name = "bytes_streamed", nullable = false)
    private long bytesStreamed;

    @Column(name = "peak_memory_bytes", nullable = false)
    private long peakMemoryBytes;

    @Column(name = "avg_rows_per_sec", nullable = false)
    private double avgRowsPerSec;

    @Column(name = "schema_drift_detected", nullable = false)
    private boolean schemaDriftDetected;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "drift_summary_json", columnDefinition = "jsonb")
    private Map<String, Object> driftSummaryJson;

    @Column(name = "error_message", columnDefinition = "text")
    private String errorMessage;

    @Column(name = "started_at")
    private OffsetDateTime startedAt;

    @Column(name = "completed_at")
    private OffsetDateTime completedAt;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt = OffsetDateTime.now();

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }
    public UUID getOrgId() { return orgId; }
    public void setOrgId(UUID orgId) { this.orgId = orgId; }
    public UUID getPolicyId() { return policyId; }
    public void setPolicyId(UUID policyId) { this.policyId = policyId; }
    public UUID getSourceConnectionId() { return sourceConnectionId; }
    public void setSourceConnectionId(UUID sourceConnectionId) { this.sourceConnectionId = sourceConnectionId; }
    public UUID getTargetConnectionId() { return targetConnectionId; }
    public void setTargetConnectionId(UUID targetConnectionId) { this.targetConnectionId = targetConnectionId; }
    public JobStatus getStatus() { return status; }
    public void setStatus(JobStatus status) { this.status = status; }
    public String getTriggerSource() { return triggerSource; }
    public void setTriggerSource(String triggerSource) { this.triggerSource = triggerSource; }
    public String getTriggeredBy() { return triggeredBy; }
    public void setTriggeredBy(String triggeredBy) { this.triggeredBy = triggeredBy; }
    public String getWorkerNodeId() { return workerNodeId; }
    public void setWorkerNodeId(String workerNodeId) { this.workerNodeId = workerNodeId; }
    public String getSaltCommitmentSha256() { return saltCommitmentSha256; }
    public void setSaltCommitmentSha256(String saltCommitmentSha256) { this.saltCommitmentSha256 = saltCommitmentSha256; }
    public int getTotalTables() { return totalTables; }
    public void setTotalTables(int totalTables) { this.totalTables = totalTables; }
    public int getCompletedTables() { return completedTables; }
    public void setCompletedTables(int completedTables) { this.completedTables = completedTables; }
    public long getRowsProcessed() { return rowsProcessed; }
    public void setRowsProcessed(long rowsProcessed) { this.rowsProcessed = rowsProcessed; }
    public long getBytesStreamed() { return bytesStreamed; }
    public void setBytesStreamed(long bytesStreamed) { this.bytesStreamed = bytesStreamed; }
    public long getPeakMemoryBytes() { return peakMemoryBytes; }
    public void setPeakMemoryBytes(long peakMemoryBytes) { this.peakMemoryBytes = peakMemoryBytes; }
    public double getAvgRowsPerSec() { return avgRowsPerSec; }
    public void setAvgRowsPerSec(double avgRowsPerSec) { this.avgRowsPerSec = avgRowsPerSec; }
    public boolean isSchemaDriftDetected() { return schemaDriftDetected; }
    public void setSchemaDriftDetected(boolean schemaDriftDetected) { this.schemaDriftDetected = schemaDriftDetected; }
    public Map<String, Object> getDriftSummaryJson() { return driftSummaryJson; }
    public void setDriftSummaryJson(Map<String, Object> driftSummaryJson) { this.driftSummaryJson = driftSummaryJson; }
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    public OffsetDateTime getStartedAt() { return startedAt; }
    public void setStartedAt(OffsetDateTime startedAt) { this.startedAt = startedAt; }
    public OffsetDateTime getCompletedAt() { return completedAt; }
    public void setCompletedAt(OffsetDateTime completedAt) { this.completedAt = completedAt; }
    public OffsetDateTime getCreatedAt() { return createdAt; }
}
