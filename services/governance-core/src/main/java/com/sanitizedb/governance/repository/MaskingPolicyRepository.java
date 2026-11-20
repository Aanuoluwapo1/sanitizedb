package com.sanitizedb.governance.repository;

import com.sanitizedb.governance.entity.MaskingPolicy;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface MaskingPolicyRepository extends JpaRepository<MaskingPolicy, UUID> {
    Optional<MaskingPolicy> findByIdAndOrgId(UUID id, UUID orgId);
    Optional<MaskingPolicy> findFirstByOrgIdAndNameOrderByVersionDesc(UUID orgId, String name);

    @Query(
        value = "SELECT * FROM masking_policies WHERE org_id = :orgId AND status = CAST(:status AS policy_status) ORDER BY version DESC LIMIT 1",
        nativeQuery = true
    )
    Optional<MaskingPolicy> findActiveByOrgId(@Param("orgId") UUID orgId, @Param("status") String status);
}
