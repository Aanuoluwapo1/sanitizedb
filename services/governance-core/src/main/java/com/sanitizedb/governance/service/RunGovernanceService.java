package com.sanitizedb.governance.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sanitizedb.governance.dto.RunRecordingDtos.*;
import com.sanitizedb.governance.entity.AuditCertificate;
import com.sanitizedb.governance.entity.MaskingPolicy;
import com.sanitizedb.governance.entity.MaskingPolicy.ColumnRuleSpec;
import com.sanitizedb.governance.entity.SyncJob;
import com.sanitizedb.governance.repository.AuditCertificateRepository;
import com.sanitizedb.governance.repository.MaskingPolicyRepository;
import com.sanitizedb.governance.repository.SyncJobRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.Year;
import java.util.*;

@Service
public class RunGovernanceService {

    private static final Logger log = LoggerFactory.getLogger(RunGovernanceService.class);

    public static final UUID DEFAULT_ORG_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    public static final UUID DEFAULT_SOURCE_CONN_ID = UUID.fromString("00000000-0000-0000-0000-000000000010");
    public static final UUID DEFAULT_TARGET_CONN_ID = UUID.fromString("00000000-0000-0000-0000-000000000020");
    public static final UUID DEFAULT_POLICY_ID = UUID.fromString("00000000-0000-0000-0000-000000000100");
    private static final String GENESIS_HASH = "0".repeat(64);

    private final SyncJobRepository syncJobRepository;
    private final AuditCertificateRepository certificateRepository;
    private final MaskingPolicyRepository policyRepository;
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final KeyPair signingKeyPair;
    private final HttpClient httpClient;
    private final String orchestratorUrl;

    public RunGovernanceService(
        SyncJobRepository syncJobRepository,
        AuditCertificateRepository certificateRepository,
        MaskingPolicyRepository policyRepository,
        JdbcTemplate jdbcTemplate,
        ObjectMapper objectMapper,
        @Value("${ORCHESTRATOR_URL:http://orchestrator:8080}") String orchestratorUrl
    ) {
        this.syncJobRepository = syncJobRepository;
        this.certificateRepository = certificateRepository;
        this.policyRepository = policyRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.signingKeyPair = initEd25519KeyPair();
        this.orchestratorUrl = orchestratorUrl.replaceAll("/+$", "");
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(4))
            .build();
    }

    @PostConstruct
    public void ensureDefaultDevSeed() {
        try {
            jdbcTemplate.update("""
                INSERT INTO organizations (id, slug, name, plan, kms_key_alias, strict_drift_gate)
                VALUES (?::uuid, 'acme-dev', 'Acme Corp (Local Dev)', 'ENTERPRISE', 'vault://transit/keys/acme-dev', TRUE)
                ON CONFLICT (id) DO NOTHING
                """, DEFAULT_ORG_ID.toString());

            jdbcTemplate.update("""
                INSERT INTO connections (id, org_id, name, engine, role, host, port, database_name, ssl_mode, vault_secret_path, read_only_enforced, created_by)
                VALUES (?::uuid, ?::uuid, 'prod_app', 'POSTGRESQL', 'SOURCE_PROD', 'source-db', 5432, 'prod_app', 'disable', 'secret/data/sanitizedb/source-db', TRUE, 'system-bootstrap')
                ON CONFLICT (id) DO NOTHING
                """, DEFAULT_SOURCE_CONN_ID.toString(), DEFAULT_ORG_ID.toString());

            jdbcTemplate.update("""
                INSERT INTO connections (id, org_id, name, engine, role, host, port, database_name, ssl_mode, vault_secret_path, read_only_enforced, created_by)
                VALUES (?::uuid, ?::uuid, 'staging_app', 'POSTGRESQL', 'TARGET_STAGING', 'target-db', 5432, 'staging_app', 'disable', 'secret/data/sanitizedb/target-db', FALSE, 'system-bootstrap')
                ON CONFLICT (id) DO NOTHING
                """, DEFAULT_TARGET_CONN_ID.toString(), DEFAULT_ORG_ID.toString());

            jdbcTemplate.update("""
                INSERT INTO masking_policies (
                    id, org_id, source_connection_id, name, version, status, frameworks,
                    rules_json, schema_baseline_json, rules_sha256, approved_by, approved_at, created_by
                ) VALUES (
                    ?::uuid, ?::uuid, ?::uuid, 'prod-to-staging-gdpr-v1', 1, 'ACTIVE',
                    ARRAY['GDPR', 'NDPR', 'PCI_DSS']::compliance_framework[],
                    '{
                      "public.users": {
                        "id": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "external_uid": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "full_name": {"strategy": "DETERMINISTIC_FAKE", "semanticType": "FULL_NAME", "deterministicDomain": "identity.full_name", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "email": {"strategy": "DETERMINISTIC_FAKE", "semanticType": "EMAIL", "deterministicDomain": "identity.email", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "phone_number": {"strategy": "DETERMINISTIC_FAKE", "semanticType": "PHONE", "deterministicDomain": "identity.phone", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "national_id": {"strategy": "DETERMINISTIC_FAKE", "semanticType": "NATIONAL_ID", "deterministicDomain": "identity.national_id", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "date_of_birth": {"strategy": "DETERMINISTIC_FAKE", "semanticType": "DATE_OF_BIRTH", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "signup_ip": {"strategy": "PARTIAL_MASK", "semanticType": "IP_ADDRESS", "deterministicDomain": "", "preservePrefix": 4, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "country_code": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "tier": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "created_at": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false}
                      },
                      "public.payment_methods": {
                        "id": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "user_id": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "cardholder_name": {"strategy": "DETERMINISTIC_FAKE", "semanticType": "FULL_NAME", "deterministicDomain": "identity.full_name", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "card_number": {"strategy": "PARTIAL_MASK", "semanticType": "CREDIT_CARD", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 4, "stewardWaiverApproved": false},
                        "billing_email": {"strategy": "DETERMINISTIC_FAKE", "semanticType": "EMAIL", "deterministicDomain": "identity.email", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "billing_zip": {"strategy": "PARTIAL_MASK", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 2, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "created_at": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false}
                      },
                      "public.orders": {
                        "id": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "user_id": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "customer_email": {"strategy": "DETERMINISTIC_FAKE", "semanticType": "EMAIL", "deterministicDomain": "identity.email", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "shipping_address": {"strategy": "DETERMINISTIC_FAKE", "semanticType": "STREET_ADDRESS", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "amount_cents": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "currency": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "status": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "created_at": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false}
                      },
                      "public.audit_logs": {
                        "id": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "user_id": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "actor_email": {"strategy": "DETERMINISTIC_FAKE", "semanticType": "EMAIL", "deterministicDomain": "identity.email", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "ip_address": {"strategy": "PARTIAL_MASK", "semanticType": "IP_ADDRESS", "deterministicDomain": "", "preservePrefix": 4, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "action": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "user_agent": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false},
                        "created_at": {"strategy": "PASS_THROUGH", "semanticType": "NONE", "deterministicDomain": "", "preservePrefix": 0, "preserveSuffix": 0, "stewardWaiverApproved": false}
                      }
                    }'::jsonb,
                    '{}'::jsonb,
                    'a3f9d0e8c4128f7b019e45263d1b7c8899e0a1b2c3d4e5f60718293a4b5c6d7e',
                    'data-steward@acme.dev',
                    NOW(),
                    'system-bootstrap'
                ) ON CONFLICT (id) DO NOTHING
                """, DEFAULT_POLICY_ID.toString(), DEFAULT_ORG_ID.toString(), DEFAULT_SOURCE_CONN_ID.toString());
            log.info("Verified default SanitizeDB dev tenant, connections, and active masking policy");
        } catch (Exception e) {
            log.warn("Could not bootstrap default dev seed: {}", e.getMessage());
        }
    }

    /**
     * Inspects live source-db columns via Orchestrator -> Rust Stream Engine and compares
     * them against the active MaskingPolicy rules to detect schema drift & unmapped PII.
     */
    @Transactional(readOnly = true)
    public PolicyDriftInspectionReport inspectActivePolicyDrift(boolean strictDriftBlock) {
        MaskingPolicy policy = getActivePolicy();
        Map<String, Map<String, ColumnRuleSpec>> rulesJson =
            Objects.requireNonNullElseGet(policy.getRulesJson(), Map::of);

        LiveSchemaPayload liveSchema = fetchLiveSourceSchema();
        List<UnmappedColumnDrift> unmappedColumns = new ArrayList<>();
        int highCount = 0;
        int mediumCount = 0;
        int lowCount = 0;

        for (LiveTableInfo tbl : liveSchema.tables()) {
            String tableId = tbl.schemaName() + "." + tbl.tableName();
            Map<String, ColumnRuleSpec> mappedCols = rulesJson.getOrDefault(tableId, Map.of());

            for (LiveColumnInfo col : tbl.columns()) {
                if (mappedCols.containsKey(col.name())) {
                    continue;
                }
                HeuristicClassification hc = classifyColumnHeuristic(col.name());
                switch (hc.riskLevel()) {
                    case "HIGH" -> highCount++;
                    case "MEDIUM" -> mediumCount++;
                    default -> lowCount++;
                }

                unmappedColumns.add(new UnmappedColumnDrift(
                    tableId,
                    tbl.schemaName(),
                    tbl.tableName(),
                    col.name(),
                    col.dataType(),
                    hc.riskLevel(),
                    hc.detectedPii(),
                    hc.confidence(),
                    hc.matchedPattern(),
                    hc.reason(),
                    hc.suggestedStrategy(),
                    hc.suggestedDomain(),
                    hc.preservePrefix(),
                    hc.preserveSuffix()
                ));
            }
        }

        boolean driftDetected = !unmappedColumns.isEmpty();
        boolean syncBlocked = strictDriftBlock && highCount > 0;

        return new PolicyDriftInspectionReport(
            policy.getId(),
            policy.getName(),
            policy.getVersion(),
            liveSchema.schemaFingerprintSha256(),
            driftDetected,
            strictDriftBlock,
            syncBlocked,
            highCount,
            mediumCount,
            lowCount,
            unmappedColumns,
            liveSchema.tables(),
            OffsetDateTime.now()
        );
    }

    private LiveSchemaPayload fetchLiveSourceSchema() {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(orchestratorUrl + "/api/v1/schema/inspect"))
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) {
                return objectMapper.readValue(resp.body(), LiveSchemaPayload.class);
            }
            log.warn("Orchestrator schema inspect returned HTTP {}: {}", resp.statusCode(), resp.body());
        } catch (Exception e) {
            log.warn("Failed to inspect live schema via orchestrator: {}", e.getMessage());
        }
        return new LiveSchemaPayload("", List.of());
    }

    private record HeuristicClassification(
        String riskLevel,
        String detectedPii,
        double confidence,
        String matchedPattern,
        String reason,
        String suggestedStrategy,
        String suggestedDomain,
        int preservePrefix,
        int preserveSuffix
    ) {}

    /**
     * Classifies an unmapped column into HIGH, MEDIUM, or LOW PII risk:
     * - HIGH:   email, phone, mobile, ssn, nin, bvn, passport, card, cvv, iban, account, address, ip, dob, birth, token, secret
     * - MEDIUM: name, user, city, country, zip, postal
     * - LOW:    otherwise
     */
    private static HeuristicClassification classifyColumnHeuristic(String columnName) {
        String col = columnName == null ? "" : columnName.trim().toLowerCase(Locale.ROOT);
        Set<String> tokens = new HashSet<>(Arrays.asList(col.split("_")));

        // 1. HIGH RISK
        if (col.contains("email") || tokens.contains("mail")) {
            return new HeuristicClassification(
                "HIGH", "EMAIL", 0.98, "email",
                "Matches email PII pattern",
                "DETERMINISTIC_FAKE", "identity.email", 0, 0
            );
        }
        if (col.contains("phone") || col.contains("mobile") || tokens.contains("tel") || tokens.contains("msisdn")) {
            String pat = col.contains("mobile") ? "mobile" : "phone";
            return new HeuristicClassification(
                "HIGH", "PHONE", 0.96, pat,
                "Matches " + pat + " PII pattern",
                "DETERMINISTIC_FAKE", "identity.phone", 0, 0
            );
        }
        for (String idPat : List.of("ssn", "nin", "bvn", "passport")) {
            if (tokens.contains(idPat) || (idPat.length() >= 4 && col.contains(idPat))) {
                return new HeuristicClassification(
                    "HIGH", "NATIONAL_ID", 0.97, idPat,
                    "Matches regulated national ID pattern '" + idPat + "'",
                    "DETERMINISTIC_FAKE", "identity.national_id", 0, 0
                );
            }
        }
        if (col.contains("national_id")) {
            return new HeuristicClassification(
                "HIGH", "NATIONAL_ID", 0.97, "nin",
                "Matches national_id PII pattern",
                "DETERMINISTIC_FAKE", "identity.national_id", 0, 0
            );
        }
        for (String finPat : List.of("card", "cvv", "iban", "account")) {
            if (tokens.contains(finPat) || col.contains("card") || col.contains("iban") || col.contains("account")) {
                String strategy = tokens.contains("cvv") ? "NULLIFY" : "PARTIAL_MASK";
                int suffix = tokens.contains("cvv") ? 0 : 4;
                return new HeuristicClassification(
                    "HIGH", "CREDIT_CARD", 0.96, finPat,
                    "Matches PCI/financial pattern '" + finPat + "'",
                    strategy, "", 0, suffix
                );
            }
        }
        if (col.contains("address")) {
            return new HeuristicClassification(
                "HIGH", "STREET_ADDRESS", 0.93, "address",
                "Matches physical street address pattern",
                "DETERMINISTIC_FAKE", "", 0, 0
            );
        }
        if (tokens.contains("ip") || tokens.contains("ipv4") || tokens.contains("ipv6")) {
            return new HeuristicClassification(
                "HIGH", "IP_ADDRESS", 0.94, "ip",
                "Matches network IP address pattern",
                "PARTIAL_MASK", "", 4, 0
            );
        }
        if (tokens.contains("dob") || col.contains("birth")) {
            String pat = tokens.contains("dob") ? "dob" : "birth";
            return new HeuristicClassification(
                "HIGH", "DATE_OF_BIRTH", 0.95, pat,
                "Matches date of birth pattern '" + pat + "'",
                "DETERMINISTIC_FAKE", "", 0, 0
            );
        }
        if (col.contains("token") || col.contains("secret")) {
            String pat = col.contains("secret") ? "secret" : "token";
            return new HeuristicClassification(
                "HIGH", "NATIONAL_ID", 0.95, pat,
                "Matches credential/secret pattern '" + pat + "'",
                "NULLIFY", "", 0, 0
            );
        }

        // 2. MEDIUM RISK
        if (col.contains("name")) {
            return new HeuristicClassification(
                "MEDIUM", "FULL_NAME", 0.85, "name",
                "Matches personal name pattern",
                "DETERMINISTIC_FAKE", "identity.full_name", 0, 0
            );
        }
        if ((tokens.contains("user") || col.contains("username")) && !col.equals("user_id") && !col.equals("user_agent")) {
            return new HeuristicClassification(
                "MEDIUM", "FULL_NAME", 0.78, "user",
                "Matches user identifier pattern",
                "DETERMINISTIC_FAKE", "identity.full_name", 0, 0
            );
        }
        for (String locPat : List.of("city", "country", "zip", "postal")) {
            if (tokens.contains(locPat) || col.contains(locPat)) {
                return new HeuristicClassification(
                    "MEDIUM", "STREET_ADDRESS", 0.76, locPat,
                    "Matches geographic location pattern '" + locPat + "'",
                    "PARTIAL_MASK", "", 2, 0
                );
            }
        }

        // 3. LOW RISK
        return new HeuristicClassification(
            "LOW", "NONE", 0.10, "none",
            "No PII heuristic pattern matched",
            "PASS_THROUGH", "", 0, 0
        );
    }

    @Transactional
    public SyncRunResponse recordSyncRun(RecordSyncRunRequest req) {
        UUID jobId = req.jobId() != null ? req.jobId() : UUID.randomUUID();
        UUID orgId = parseUuidOrDefault(req.orgId(), DEFAULT_ORG_ID);
        UUID sourceConnId = parseUuidOrDefault(req.sourceConnectionId(), DEFAULT_SOURCE_CONN_ID);
        UUID targetConnId = parseUuidOrDefault(req.targetConnectionId(), DEFAULT_TARGET_CONN_ID);

        MaskingPolicy policy = resolvePolicy(orgId, req.policyId());
        SyncJob.JobStatus status = parseStatus(req.status());
        List<TableRunSummary> tables = req.tables() != null ? req.tables() : List.of();
        int completedTables = (int) tables.stream().filter(TableRunSummary::completed).count();

        String saltCommitment = (req.saltCommitmentSha256() != null && req.saltCommitmentSha256().length() == 64)
            ? req.saltCommitmentSha256()
            : "0".repeat(64);

        SyncJob job = syncJobRepository.findById(jobId).orElseGet(SyncJob::new);
        job.setId(jobId);
        job.setOrgId(orgId);
        job.setPolicyId(policy.getId());
        job.setSourceConnectionId(sourceConnId);
        job.setTargetConnectionId(targetConnId);
        job.setStatus(status);
        job.setTriggerSource(req.triggerSource() != null && !req.triggerSource().isBlank() ? req.triggerSource() : "CLI_CI");
        job.setTriggeredBy(req.triggeredBy() != null && !req.triggeredBy().isBlank() ? req.triggeredBy() : "orchestrator");
        job.setWorkerNodeId(req.workerNodeId() != null ? req.workerNodeId() : "stream-engine:50051");
        job.setSaltCommitmentSha256(saltCommitment);
        job.setTotalTables(tables.size());
        job.setCompletedTables(completedTables);
        job.setRowsProcessed(req.totalRowsMasked());
        job.setBytesStreamed(req.totalBytesStreamed());
        job.setAvgRowsPerSec(req.avgRowsPerSec());
        job.setSchemaDriftDetected(req.schemaDriftDetected() || status == SyncJob.JobStatus.BLOCKED_DRIFT);
        job.setErrorMessage(req.errorMessage());
        job.setStartedAt(req.startedAt() != null ? req.startedAt() : OffsetDateTime.now());
        job.setCompletedAt(req.completedAt() != null ? req.completedAt() : OffsetDateTime.now());

        Map<String, Object> summaryMeta = new LinkedHashMap<>();
        summaryMeta.put("durationMs", req.durationMs());
        summaryMeta.put("tables", tables);
        job.setDriftSummaryJson(summaryMeta);

        SyncJob savedJob = syncJobRepository.saveAndFlush(job);

        AuditCertificate cert = null;
        if (status == SyncJob.JobStatus.SUCCEEDED && req.zeroDiskWritesVerified()) {
            cert = certificateRepository.findBySyncJobId(savedJob.getId())
                .orElseGet(() -> mintCertificate(savedJob, policy, req, tables));
        }

        return new SyncRunResponse(savedJob, cert);
    }

    @Transactional(readOnly = true)
    public List<SyncRunResponse> listRecentRuns() {
        List<SyncJob> jobs = syncJobRepository.findTop25ByOrderByCreatedAtDesc();
        List<SyncRunResponse> out = new ArrayList<>(jobs.size());
        for (SyncJob j : jobs) {
            AuditCertificate cert = certificateRepository.findBySyncJobId(j.getId()).orElse(null);
            out.add(new SyncRunResponse(j, cert));
        }
        return out;
    }

    @Transactional(readOnly = true)
    public List<AuditCertificate> listRecentCertificates() {
        return certificateRepository.findTop25ByOrderByIssuedAtDesc();
    }

    @Transactional(readOnly = true)
    public MaskingPolicy getActivePolicy() {
        return policyRepository.findActiveByOrgId(DEFAULT_ORG_ID, MaskingPolicy.PolicyStatus.ACTIVE.name())
            .orElseThrow(() -> new IllegalStateException("No active masking policy found"));
    }

    @Transactional
    public MaskingPolicy updatePolicyRules(UUID policyId, PolicyRulesUpdateRequest req) {
        MaskingPolicy policy = policyRepository.findById(policyId)
            .orElseThrow(() -> new IllegalArgumentException("MaskingPolicy not found: " + policyId));
        if (req.rulesJson() == null || req.rulesJson().isEmpty()) {
            throw new IllegalArgumentException("rulesJson must not be empty");
        }
        policy.setRulesJson(req.rulesJson());
        try {
            byte[] canonical = objectMapper.writeValueAsBytes(req.rulesJson());
            policy.setRulesSha256(sha256Hex(canonical));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to hash updated policy rules", e);
        }
        return policyRepository.save(policy);
    }

    private synchronized AuditCertificate mintCertificate(
        SyncJob job,
        MaskingPolicy policy,
        RecordSyncRunRequest req,
        List<TableRunSummary> tables
    ) {
        String previousHash = certificateRepository.findTopByOrgIdOrderByIssuedAtDesc(job.getOrgId())
            .map(AuditCertificate::getPayloadSha256)
            .orElse(GENESIS_HASH);

        String serial = "SDB-%d-%s".formatted(
            Year.now().getValue(),
            UUID.randomUUID().toString().substring(0, 8).toUpperCase(Locale.ROOT)
        );

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("certificateSerial", serial);
        payload.put("jobId", job.getId().toString());
        payload.put("orgId", job.getOrgId().toString());
        payload.put("sourceConnectionId", job.getSourceConnectionId().toString());
        payload.put("targetConnectionId", job.getTargetConnectionId().toString());
        payload.put("policyId", policy.getId().toString());
        payload.put("policyName", policy.getName());
        payload.put("policyVersion", policy.getVersion());
        payload.put("policyRulesSha256", policy.getRulesSha256());
        payload.put("saltCommitmentSha256", job.getSaltCommitmentSha256());
        payload.put("totalRowsMasked", req.totalRowsMasked());
        payload.put("totalBytesStreamed", req.totalBytesStreamed());
        payload.put("durationMs", req.durationMs());
        payload.put("tableSummaries", tables);
        payload.put("engineVersion", req.engineVersion() != null ? req.engineVersion() : "0.1.0");
        payload.put("zeroDiskWritesVerified", true);
        payload.put("issuedAt", Instant.now().toString());

        try {
            byte[] canonicalBytes = objectMapper.writeValueAsBytes(payload);
            String payloadSha256 = sha256Hex(canonicalBytes);

            String chainMaterial = previousHash + ":" + payloadSha256;
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(signingKeyPair.getPrivate());
            sig.update(chainMaterial.getBytes(StandardCharsets.UTF_8));
            String signatureB64 = Base64.getEncoder().encodeToString(sig.sign());

            AuditCertificate cert = new AuditCertificate();
            cert.setOrgId(job.getOrgId());
            cert.setSyncJobId(job.getId());
            cert.setPolicyId(policy.getId());
            cert.setPolicyVersion(policy.getVersion());
            cert.setCertificateSerial(serial);
            cert.setCertificatePayload(payload);
            cert.setPayloadSha256(payloadSha256);
            cert.setPreviousCertHash(previousHash);
            cert.setSignatureAlgorithm("ED25519");
            cert.setSignatureBase64(signatureB64);
            cert.setSigningKeyId("kms-ed25519-dev-v1");

            return certificateRepository.saveAndFlush(cert);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign compliance audit certificate", e);
        }
    }

    private MaskingPolicy resolvePolicy(UUID orgId, String policyRef) {
        if (policyRef != null && !policyRef.isBlank()) {
            try {
                UUID pid = UUID.fromString(policyRef);
                Optional<MaskingPolicy> byId = policyRepository.findByIdAndOrgId(pid, orgId);
                if (byId.isPresent()) return byId.get();
            } catch (IllegalArgumentException ignored) {
                Optional<MaskingPolicy> byName = policyRepository.findFirstByOrgIdAndNameOrderByVersionDesc(orgId, policyRef);
                if (byName.isPresent()) return byName.get();
            }
        }
        return policyRepository.findActiveByOrgId(orgId, MaskingPolicy.PolicyStatus.ACTIVE.name())
            .orElseThrow(() -> new IllegalArgumentException("No active MaskingPolicy found for org " + orgId));
    }

    private static UUID parseUuidOrDefault(String raw, UUID fallback) {
        if (raw == null || raw.isBlank()) return fallback;
        try {
            return UUID.fromString(raw);
        } catch (IllegalArgumentException e) {
            return fallback;
        }
    }

    private static SyncJob.JobStatus parseStatus(String raw) {
        if (raw == null) return SyncJob.JobStatus.FAILED;
        try {
            return SyncJob.JobStatus.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return SyncJob.JobStatus.FAILED;
        }
    }

    private static String sha256Hex(byte[] input) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(input);
        return HexFormat.of().formatHex(digest);
    }

    private static KeyPair initEd25519KeyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("JDK 21 Ed25519 provider unavailable", e);
        }
    }
}
