package com.sanitizedb.governance.repository;

import com.sanitizedb.governance.entity.AuditCertificate;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuditCertificateRepository extends JpaRepository<AuditCertificate, UUID> {
    Optional<AuditCertificate> findTopByOrgIdOrderByIssuedAtDesc(UUID orgId);
    Optional<AuditCertificate> findBySyncJobId(UUID syncJobId);
    List<AuditCertificate> findTop25ByOrderByIssuedAtDesc();
}
