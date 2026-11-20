package com.sanitizedb.governance.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.Immutable;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

/**
 * Immutable, tamper-evident compliance certificate persisted after every verified
 * staging anonymization run. Paired with a PostgreSQL BEFORE UPDATE/DELETE trigger
 * to enforce append-only audit integrity.
 */
@Entity
@Immutable
@Table(name = "audit_certificates")
public class AuditCertificate {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "org_id", nullable = false, updatable = false)
    private UUID orgId;

    @Column(name = "sync_job_id", nullable = false, unique = true, updatable = false)
    private UUID syncJobId;

    @Column(name = "policy_id", nullable = false, updatable = false)
    private UUID policyId;

    @Column(name = "policy_version", nullable = false, updatable = false)
    private Integer policyVersion;

    @Column(name = "certificate_serial", nullable = false, unique = true, length = 64, updatable = false)
    private String certificateSerial;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "certificate_payload", nullable = false, columnDefinition = "jsonb", updatable = false)
    private Map<String, Object> certificatePayload;

    @Column(name = "payload_sha256", nullable = false, length = 64, updatable = false)
    private String payloadSha256;

    @Column(name = "previous_cert_hash", nullable = false, length = 64, updatable = false)
    private String previousCertHash;

    @Column(name = "signature_algorithm", nullable = false, length = 32, updatable = false)
    private String signatureAlgorithm = "ED25519";

    @Column(name = "signature_base64", nullable = false, columnDefinition = "text", updatable = false)
    private String signatureBase64;

    @Column(name = "signing_key_id", nullable = false, length = 128, updatable = false)
    private String signingKeyId;

    @Column(name = "issued_at", nullable = false, updatable = false)
    private OffsetDateTime issuedAt = OffsetDateTime.now();

    public UUID getId() { return id; }
    public UUID getOrgId() { return orgId; }
    public void setOrgId(UUID orgId) { this.orgId = orgId; }
    public UUID getSyncJobId() { return syncJobId; }
    public void setSyncJobId(UUID syncJobId) { this.syncJobId = syncJobId; }
    public UUID getPolicyId() { return policyId; }
    public void setPolicyId(UUID policyId) { this.policyId = policyId; }
    public Integer getPolicyVersion() { return policyVersion; }
    public void setPolicyVersion(Integer policyVersion) { this.policyVersion = policyVersion; }
    public String getCertificateSerial() { return certificateSerial; }
    public void setCertificateSerial(String certificateSerial) { this.certificateSerial = certificateSerial; }
    public Map<String, Object> getCertificatePayload() { return certificatePayload; }
    public void setCertificatePayload(Map<String, Object> certificatePayload) { this.certificatePayload = certificatePayload; }
    public String getPayloadSha256() { return payloadSha256; }
    public void setPayloadSha256(String payloadSha256) { this.payloadSha256 = payloadSha256; }
    public String getPreviousCertHash() { return previousCertHash; }
    public void setPreviousCertHash(String previousCertHash) { this.previousCertHash = previousCertHash; }
    public String getSignatureAlgorithm() { return signatureAlgorithm; }
    public void setSignatureAlgorithm(String signatureAlgorithm) { this.signatureAlgorithm = signatureAlgorithm; }
    public String getSignatureBase64() { return signatureBase64; }
    public void setSignatureBase64(String signatureBase64) { this.signatureBase64 = signatureBase64; }
    public String getSigningKeyId() { return signingKeyId; }
    public void setSigningKeyId(String signingKeyId) { this.signingKeyId = signingKeyId; }
    public OffsetDateTime getIssuedAt() { return issuedAt; }
}
