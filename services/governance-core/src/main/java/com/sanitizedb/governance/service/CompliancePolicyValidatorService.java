package com.sanitizedb.governance.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sanitizedb.governance.dto.SchemaDriftDtos.*;
import com.sanitizedb.governance.entity.AuditCertificate;
import com.sanitizedb.governance.entity.MaskingPolicy;
import com.sanitizedb.governance.entity.MaskingPolicy.ColumnRuleSpec;
import com.sanitizedb.governance.repository.AuditCertificateRepository;
import com.sanitizedb.governance.repository.MaskingPolicyRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.time.Year;
import java.util.*;

@Service
public class CompliancePolicyValidatorService {

    private static final Set<String> REGULATED_PII_CATEGORIES = Set.of(
        "EMAIL", "PHONE", "CREDIT_CARD", "NATIONAL_ID",
        "IP_ADDRESS", "FULL_NAME", "STREET_ADDRESS", "DATE_OF_BIRTH"
    );
    private static final double PII_ALERT_THRESHOLD = 0.70;
    private static final String GENESIS_HASH = "0".repeat(64);

    private final MaskingPolicyRepository policyRepository;
    private final AuditCertificateRepository certificateRepository;
    private final ObjectMapper objectMapper;
    private final KeyPair signingKeyPair;

    public CompliancePolicyValidatorService(
        MaskingPolicyRepository policyRepository,
        AuditCertificateRepository certificateRepository,
        ObjectMapper objectMapper
    ) {
        this.policyRepository = policyRepository;
        this.certificateRepository = certificateRepository;
        this.objectMapper = objectMapper;
        this.signingKeyPair = initEphemeralEd25519KeyPair();
    }

    /**
     * Validates a live source schema snapshot against a tenant's approved MaskingPolicy.
     * Detects newly introduced production columns (schema drift) and prevents regulated
     * PII from passing through unmasked under GDPR, NDPR, HIPAA, or PCI-DSS.
     */
    @Transactional(readOnly = true)
    public ComplianceValidationResult validatePolicyAgainstLiveSchema(SchemaValidationRequest request) {
        MaskingPolicy policy = policyRepository.findByIdAndOrgId(request.policyId(), request.orgId())
            .orElseThrow(() -> new IllegalArgumentException("MaskingPolicy not found for tenant"));

        List<ComplianceFinding> findings = new ArrayList<>();
        boolean driftDetected = false;

        if (policy.getStatus() != MaskingPolicy.PolicyStatus.ACTIVE) {
            findings.add(new ComplianceFinding(
                "CRITICAL",
                "POLICY_NOT_ACTIVE",
                "*",
                "Policy version %d is in status %s; only ACTIVE approved policies can run against staging."
                    .formatted(policy.getVersion(), policy.getStatus())
            ));
        }

        Map<String, Map<String, ColumnRuleSpec>> configuredTables =
            Objects.requireNonNullElseGet(policy.getRulesJson(), Map::of);

        for (ObservedColumn col : request.liveSourceColumns()) {
            String fqCol = col.tableQualifiedName() + "." + col.columnName();
            boolean isSensitivePii = REGULATED_PII_CATEGORIES.contains(col.detectedPiiCategory())
                && col.piiConfidence() >= PII_ALERT_THRESHOLD;

            Map<String, ColumnRuleSpec> tableRules = configuredTables.get(col.tableQualifiedName());
            ColumnRuleSpec rule = tableRules == null ? null : tableRules.get(col.columnName());

            // 1. Schema Drift Check: Column exists in live production DB but is absent from approved policy
            if (rule == null) {
                driftDetected = true;
                if (isSensitivePii) {
                    findings.add(new ComplianceFinding(
                        request.strictDriftGate() ? "CRITICAL" : "WARNING",
                        "SCHEMA_DRIFT_UNMAPPED_PII",
                        fqCol,
                        "Schema drift detected: new column '%s' flagged as %s (%.0f%% confidence) has no masking rule."
                            .formatted(fqCol, col.detectedPiiCategory(), col.piiConfidence() * 100.0)
                    ));
                } else {
                    findings.add(new ComplianceFinding(
                        "WARNING",
                        "SCHEMA_DRIFT_UNMAPPED_COLUMN",
                        fqCol,
                        "New non-PII column '%s' detected since policy v%d baseline.".formatted(fqCol, policy.getVersion())
                    ));
                }
                continue;
            }

            // 2. Regulatory Rule Enforcement: Regulated PII cannot use PASS_THROUGH without Steward waiver
            if (isSensitivePii && "PASS_THROUGH".equalsIgnoreCase(rule.strategy()) && !rule.stewardWaiverApproved()) {
                findings.add(new ComplianceFinding(
                    "CRITICAL",
                    "UNMASKED_PII_PASS_THROUGH",
                    fqCol,
                    "Column '%s' (%s) cannot use PASS_THROUGH under %s without a Data Steward waiver."
                        .formatted(fqCol, col.detectedPiiCategory(), String.join("/", request.complianceFrameworks()))
                ));
            }
        }

        boolean hasCritical = findings.stream().anyMatch(f -> "CRITICAL".equals(f.severity()));
        return new ComplianceValidationResult(!hasCritical, driftDetected, findings);
    }

    /**
     * Mints an immutable, hash-chained, Ed25519-signed compliance certificate proving
     * a staging refresh completed with zero-disk-leak attestation.
     */
    @Transactional
    public AuditCertificate issueSignedCertificate(IssueCertificateRequest req) {
        if (!req.zeroDiskWritesVerified()) {
            throw new IllegalStateException("Cannot certify a run without Rust engine zero-disk-leak attestation");
        }

        MaskingPolicy policy = policyRepository.findByIdAndOrgId(req.policyId(), req.orgId())
            .orElseThrow(() -> new IllegalArgumentException("Policy not found for tenant"));

        String previousHash = certificateRepository.findTopByOrgIdOrderByIssuedAtDesc(req.orgId())
            .map(AuditCertificate::getPayloadSha256)
            .orElse(GENESIS_HASH);

        String serial = "SDB-%d-%s".formatted(
            Year.now().getValue(),
            UUID.randomUUID().toString().substring(0, 8).toUpperCase(Locale.ROOT)
        );

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("certificateSerial", serial);
        payload.put("orgId", req.orgId().toString());
        payload.put("syncJobId", req.syncJobId().toString());
        payload.put("policyId", policy.getId().toString());
        payload.put("policyVersion", policy.getVersion());
        payload.put("policyRulesSha256", policy.getRulesSha256());
        payload.put("saltCommitmentSha256", req.saltCommitmentSha256());
        payload.put("totalRowsMasked", req.totalRowsMasked());
        payload.put("engineVersion", req.engineVersion());
        payload.put("zeroDiskWritesVerified", true);
        payload.put("issuedAt", Instant.now().toString());

        try {
            byte[] canonicalBytes = objectMapper.writeValueAsBytes(payload);
            String payloadSha256 = sha256Hex(canonicalBytes);

            // Sign (previousCertHash || ":" || payloadSha256) with Ed25519 (replace with KMS/HSM in production)
            String chainMaterial = previousHash + ":" + payloadSha256;
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(signingKeyPair.getPrivate());
            sig.update(chainMaterial.getBytes(StandardCharsets.UTF_8));
            String signatureB64 = Base64.getEncoder().encodeToString(sig.sign());

            AuditCertificate cert = new AuditCertificate();
            cert.setOrgId(req.orgId());
            cert.setSyncJobId(req.syncJobId());
            cert.setPolicyId(policy.getId());
            cert.setPolicyVersion(policy.getVersion());
            cert.setCertificateSerial(serial);
            cert.setCertificatePayload(payload);
            cert.setPayloadSha256(payloadSha256);
            cert.setPreviousCertHash(previousHash);
            cert.setSignatureAlgorithm("ED25519");
            cert.setSignatureBase64(signatureB64);
            cert.setSigningKeyId("kms-ed25519-dev-v1");

            return certificateRepository.save(cert);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign compliance audit certificate", e);
        }
    }

    private static String sha256Hex(byte[] input) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(input);
        return HexFormat.of().formatHex(digest);
    }

    private static KeyPair initEphemeralEd25519KeyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("JDK 21 Ed25519 provider unavailable", e);
        }
    }
}
