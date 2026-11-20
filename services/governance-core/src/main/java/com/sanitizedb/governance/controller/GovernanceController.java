package com.sanitizedb.governance.controller;

import com.sanitizedb.governance.dto.RunRecordingDtos.*;
import com.sanitizedb.governance.dto.SchemaDriftDtos.*;
import com.sanitizedb.governance.entity.AuditCertificate;
import com.sanitizedb.governance.entity.MaskingPolicy;
import com.sanitizedb.governance.service.CompliancePolicyValidatorService;
import com.sanitizedb.governance.service.RunGovernanceService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/governance")
public class GovernanceController {

    private final CompliancePolicyValidatorService validatorService;
    private final RunGovernanceService runGovernanceService;

    public GovernanceController(
        CompliancePolicyValidatorService validatorService,
        RunGovernanceService runGovernanceService
    ) {
        this.validatorService = validatorService;
        this.runGovernanceService = runGovernanceService;
    }

    @GetMapping("/healthz")
    public ResponseEntity<Map<String, String>> healthz() {
        return ResponseEntity.ok(Map.of("status", "ok", "service", "governance-core"));
    }

    @GetMapping("/policies/active")
    public ResponseEntity<MaskingPolicy> getActivePolicy() {
        return ResponseEntity.ok(runGovernanceService.getActivePolicy());
    }

    @GetMapping("/policies/active/drift")
    public ResponseEntity<PolicyDriftInspectionReport> inspectActivePolicyDrift(
        @RequestParam(name = "strictDriftBlock", defaultValue = "true") boolean strictDriftBlock
    ) {
        return ResponseEntity.ok(runGovernanceService.inspectActivePolicyDrift(strictDriftBlock));
    }

    @PutMapping("/policies/{policyId}/rules")
    public ResponseEntity<MaskingPolicy> updatePolicyRules(
        @PathVariable UUID policyId,
        @RequestBody PolicyRulesUpdateRequest request
    ) {
        return ResponseEntity.ok(runGovernanceService.updatePolicyRules(policyId, request));
    }

    @PostMapping("/runs")
    public ResponseEntity<SyncRunResponse> recordSyncRun(@RequestBody RecordSyncRunRequest request) {
        return ResponseEntity.ok(runGovernanceService.recordSyncRun(request));
    }

    @GetMapping("/runs")
    public ResponseEntity<List<SyncRunResponse>> listRecentRuns() {
        return ResponseEntity.ok(runGovernanceService.listRecentRuns());
    }

    @GetMapping("/certificates")
    public ResponseEntity<List<AuditCertificate>> listCertificates() {
        return ResponseEntity.ok(runGovernanceService.listRecentCertificates());
    }

    @PostMapping("/policies/validate-drift")
    @PreAuthorize("hasAnyRole('ADMIN', 'DATA_STEWARD', 'DEVELOPER')")
    public ResponseEntity<ComplianceValidationResult> validateSchemaDrift(
        @RequestBody SchemaValidationRequest request
    ) {
        return ResponseEntity.ok(validatorService.validatePolicyAgainstLiveSchema(request));
    }

    @PostMapping("/certificates")
    @PreAuthorize("hasAnyRole('ADMIN', 'DATA_STEWARD', 'SYSTEM_ORCHESTRATOR')")
    public ResponseEntity<AuditCertificate> issueCertificate(
        @RequestBody IssueCertificateRequest request
    ) {
        return ResponseEntity.ok(validatorService.issueSignedCertificate(request));
    }
}
