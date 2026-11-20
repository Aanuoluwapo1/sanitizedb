package com.sanitizedb.governance.repository;

import com.sanitizedb.governance.entity.SyncJob;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface SyncJobRepository extends JpaRepository<SyncJob, UUID> {
    List<SyncJob> findTop25ByOrderByCreatedAtDesc();
}
