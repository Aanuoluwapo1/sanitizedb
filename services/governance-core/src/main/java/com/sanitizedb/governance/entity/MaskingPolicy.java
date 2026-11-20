package com.sanitizedb.governance.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import org.hibernate.annotations.ColumnTransformer;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(
    name = "masking_policies",
    uniqueConstraints = @UniqueConstraint(columnNames = {"org_id", "name", "version"})
)
public class MaskingPolicy {

    public enum PolicyStatus {
        DRAFT, PENDING_APPROVAL, ACTIVE, ARCHIVED
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "org_id", nullable = false)
    private UUID orgId;

    @Column(name = "source_connection_id", nullable = false)
    private UUID sourceConnectionId;

    @Column(nullable = false, length = 128)
    private String name;

    @Column(nullable = false)
    private Integer version;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @ColumnTransformer(write = "?::policy_status")
    private PolicyStatus status = PolicyStatus.DRAFT;

    /**
     * Canonical JSONB column rule map:
     * { "public.users": { "email": { "strategy": "DETERMINISTIC_FAKE", "semanticType": "EMAIL", ... } } }
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "rules_json", nullable = false, columnDefinition = "jsonb")
    private Map<String, Map<String, ColumnRuleSpec>> rulesJson;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "schema_baseline_json", nullable = false, columnDefinition = "jsonb")
    private Map<String, Object> schemaBaselineJson;

    @Column(name = "rules_sha256", nullable = false, length = 64)
    private String rulesSha256;

    @Column(name = "approved_by")
    private String approvedBy;

    @Column(name = "approved_at")
    private OffsetDateTime approvedAt;

    @Column(name = "created_by", nullable = false)
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt = OffsetDateTime.now();

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ColumnRuleSpec(
        String strategy,
        String semanticType,
        String deterministicDomain,
        int preservePrefix,
        int preserveSuffix,
        boolean stewardWaiverApproved
    ) {}

    public UUID getId() { return id; }
    public UUID getOrgId() { return orgId; }
    public void setOrgId(UUID orgId) { this.orgId = orgId; }
    public UUID getSourceConnectionId() { return sourceConnectionId; }
    public void setSourceConnectionId(UUID sourceConnectionId) { this.sourceConnectionId = sourceConnectionId; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public Integer getVersion() { return version; }
    public void setVersion(Integer version) { this.version = version; }
    public PolicyStatus getStatus() { return status; }
    public void setStatus(PolicyStatus status) { this.status = status; }
    public Map<String, Map<String, ColumnRuleSpec>> getRulesJson() { return rulesJson; }
    public void setRulesJson(Map<String, Map<String, ColumnRuleSpec>> rulesJson) { this.rulesJson = rulesJson; }
    public Map<String, Object> getSchemaBaselineJson() { return schemaBaselineJson; }
    public void setSchemaBaselineJson(Map<String, Object> schemaBaselineJson) { this.schemaBaselineJson = schemaBaselineJson; }
    public String getRulesSha256() { return rulesSha256; }
    public void setRulesSha256(String rulesSha256) { this.rulesSha256 = rulesSha256; }
    public String getApprovedBy() { return approvedBy; }
    public void setApprovedBy(String approvedBy) { this.approvedBy = approvedBy; }
    public OffsetDateTime getApprovedAt() { return approvedAt; }
    public void setApprovedAt(OffsetDateTime approvedAt) { this.approvedAt = approvedAt; }
    public String getCreatedBy() { return createdBy; }
    public void setCreatedBy(String createdBy) { this.createdBy = createdBy; }
    public OffsetDateTime getCreatedAt() { return createdAt; }
}
