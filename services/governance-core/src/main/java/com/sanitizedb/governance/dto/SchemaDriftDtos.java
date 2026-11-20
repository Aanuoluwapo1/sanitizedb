package com.sanitizedb.governance.dto;

import java.util.List;
import java.util.UUID;

public final class SchemaDriftDtos {

    private SchemaDriftDtos() {}

    public record ObservedColumn(
        String tableQualifiedName,
        String columnName,
        String dataType,
        String detectedPiiCategory, // EMAIL, CREDIT_CARD, NATIONAL_ID, PHONE, FULL_NAME, NONE
        double piiConfidence
    ) {}

    public record SchemaValidationRequest(
        UUID orgId,
        UUID policyId,
        boolean strictDriftGate,
        List<String> complianceFrameworks,
        List<ObservedColumn> liveSourceColumns
    ) {}

    public record ComplianceFinding(
        String severity, // CRITICAL | WARNING
        String code,     // SCHEMA_DRIFT_UNMAPPED_PII | UNMASKED_PII_PASS_THROUGH | POLICY_NOT_ACTIVE
        String qualifiedColumn,
        String message
    ) {}

    public record ComplianceValidationResult(
        boolean approvedForExecution,
        boolean schemaDriftDetected,
        List<ComplianceFinding> findings
    ) {}

    public record IssueCertificateRequest(
        UUID orgId,
        UUID syncJobId,
        UUID policyId,
        long totalRowsMasked,
        String saltCommitmentSha256,
        String engineVersion,
        boolean zeroDiskWritesVerified
    ) {}
}
