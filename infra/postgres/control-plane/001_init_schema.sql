-- =============================================================================
-- SanitizeDB Control Plane Database Schema (PostgreSQL 16+)
-- Tables: organizations, connections, masking_policies, sync_jobs, audit_certificates
-- Security: Multi-tenant isolation via org_id, Vault/KMS secret references only
--           (zero plaintext DB credentials stored), tamper-evident hash chain.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------------------------
-- Custom Enums
-- -----------------------------------------------------------------------------
CREATE TYPE tenant_plan AS ENUM ('STARTER', 'GROWTH', 'ENTERPRISE', 'SELF_HOSTED');
CREATE TYPE org_role AS ENUM ('ADMIN', 'DATA_STEWARD', 'DEVELOPER', 'AUDITOR');
CREATE TYPE db_engine AS ENUM ('POSTGRESQL', 'MYSQL');
CREATE TYPE connection_role AS ENUM ('SOURCE_PROD', 'TARGET_STAGING');
CREATE TYPE policy_status AS ENUM ('DRAFT', 'PENDING_APPROVAL', 'ACTIVE', 'ARCHIVED');
CREATE TYPE job_status AS ENUM ('QUEUED', 'VALIDATING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED', 'BLOCKED_DRIFT');
CREATE TYPE compliance_framework AS ENUM ('GDPR', 'NDPR', 'HIPAA', 'SOC2', 'PCI_DSS');

-- -----------------------------------------------------------------------------
-- 1. Organizations (Multi-Tenant Root)
-- -----------------------------------------------------------------------------
CREATE TABLE organizations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug                VARCHAR(63) NOT NULL UNIQUE,
    name                VARCHAR(255) NOT NULL,
    plan                tenant_plan NOT NULL DEFAULT 'STARTER',
    license_key_hash    CHAR(64),
    kms_key_alias       VARCHAR(255) NOT NULL, -- e.g., vault://transit/keys/org-acme
    strict_drift_gate   BOOLEAN NOT NULL DEFAULT TRUE, -- Block sync if unmapped PII column appears
    retention_days      INTEGER NOT NULL DEFAULT 365 CHECK (retention_days >= 30),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Organization RBAC memberships (supports Governance Core @PreAuthorize)
CREATE TABLE organization_members (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    external_subject    VARCHAR(255) NOT NULL, -- OIDC/SAML sub claim
    email               VARCHAR(320) NOT NULL,
    role                org_role NOT NULL DEFAULT 'DEVELOPER',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, external_subject)
);

CREATE INDEX idx_org_members_org_role ON organization_members (org_id, role);

-- -----------------------------------------------------------------------------
-- 2. Connections (Zero Plaintext Credentials — Vault/KMS Secret URIs Only)
-- -----------------------------------------------------------------------------
CREATE TABLE connections (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                    VARCHAR(128) NOT NULL,
    engine                  db_engine NOT NULL,
    role                    connection_role NOT NULL,
    host                    VARCHAR(255) NOT NULL,
    port                    INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    database_name           VARCHAR(128) NOT NULL,
    ssl_mode                VARCHAR(32) NOT NULL DEFAULT 'verify-full',
    -- Reference to HashiCorp Vault KVv2 / AWS Secrets Manager / GCP Secret Manager
    vault_secret_path       VARCHAR(512) NOT NULL,
    -- Optional envelope-encrypted DSN fallback for air-gapped self-hosted deployments
    encrypted_dsn_ciphertext BYTEA,
    kms_key_version         INTEGER NOT NULL DEFAULT 1,
    read_only_enforced      BOOLEAN NOT NULL DEFAULT TRUE,
    last_schema_fingerprint CHAR(64), -- SHA-256 of canonical information_schema snapshot
    last_inspected_at       TIMESTAMPTZ,
    created_by              VARCHAR(255) NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name),
    -- Safety guardrail: SOURCE_PROD connections must enforce read-only mode
    CONSTRAINT chk_source_readonly CHECK (role <> 'SOURCE_PROD' OR read_only_enforced = TRUE)
);

CREATE INDEX idx_connections_org_role ON connections (org_id, role);

-- -----------------------------------------------------------------------------
-- 3. Masking Policies (Versioned JSON/YAML Rules + Schema Snapshot Baseline)
-- -----------------------------------------------------------------------------
CREATE TABLE masking_policies (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source_connection_id    UUID NOT NULL REFERENCES connections(id) ON DELETE RESTRICT,
    name                    VARCHAR(128) NOT NULL,
    version                 INTEGER NOT NULL CHECK (version >= 1),
    status                  policy_status NOT NULL DEFAULT 'DRAFT',
    frameworks              compliance_framework[] NOT NULL DEFAULT ARRAY['GDPR']::compliance_framework[],
    -- Canonical rule tree: { "tables": { "public.users": { "columns": { "email": { "strategy": "DETERMINISTIC_FAKE", ... } } } } }
    rules_json              JSONB NOT NULL,
    -- Baseline schema snapshot at policy approval time for schema-drift validation
    schema_baseline_json    JSONB NOT NULL DEFAULT '{}'::jsonb,
    rules_sha256            CHAR(64) NOT NULL,
    cron_schedule           VARCHAR(64), -- Optional cron expr for automated staging refresh
    approved_by             VARCHAR(255),
    approved_at             TIMESTAMPTZ,
    created_by              VARCHAR(255) NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name, version)
);

CREATE INDEX idx_masking_policies_org_active ON masking_policies (org_id, status) WHERE status = 'ACTIVE';
CREATE INDEX idx_masking_policies_rules_gin ON masking_policies USING GIN (rules_json jsonb_path_ops);

-- -----------------------------------------------------------------------------
-- 4. Sync Jobs (Execution Ledger & Real-Time Telemetry Snapshots)
-- -----------------------------------------------------------------------------
CREATE TABLE sync_jobs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    policy_id               UUID NOT NULL REFERENCES masking_policies(id) ON DELETE RESTRICT,
    source_connection_id    UUID NOT NULL REFERENCES connections(id) ON DELETE RESTRICT,
    target_connection_id    UUID NOT NULL REFERENCES connections(id) ON DELETE RESTRICT,
    status                  job_status NOT NULL DEFAULT 'QUEUED',
    trigger_source          VARCHAR(32) NOT NULL DEFAULT 'WEB_UI', -- WEB_UI, CLI_CI, CRON, API
    triggered_by            VARCHAR(255) NOT NULL,
    worker_node_id          VARCHAR(128),
    -- Per-job salt is NEVER stored in plaintext; only its KMS-wrapped key ID / hash commitment is recorded
    salt_commitment_sha256  CHAR(64) NOT NULL,
    total_tables            INTEGER NOT NULL DEFAULT 0,
    completed_tables        INTEGER NOT NULL DEFAULT 0,
    rows_processed          BIGINT NOT NULL DEFAULT 0,
    bytes_streamed          BIGINT NOT NULL DEFAULT 0,
    peak_memory_bytes       BIGINT NOT NULL DEFAULT 0,
    avg_rows_per_sec        DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    schema_drift_detected   BOOLEAN NOT NULL DEFAULT FALSE,
    drift_summary_json      JSONB,
    error_message           TEXT,
    started_at              TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_distinct_connections CHECK (source_connection_id <> target_connection_id)
);

CREATE INDEX idx_sync_jobs_org_created ON sync_jobs (org_id, created_at DESC);
CREATE INDEX idx_sync_jobs_status ON sync_jobs (status) WHERE status IN ('QUEUED', 'VALIDATING', 'RUNNING');

-- -----------------------------------------------------------------------------
-- 5. Audit Certificates (Immutable, Tamper-Evident Compliance Ledger)
-- -----------------------------------------------------------------------------
CREATE TABLE audit_certificates (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    sync_job_id             UUID NOT NULL UNIQUE REFERENCES sync_jobs(id) ON DELETE RESTRICT,
    policy_id               UUID NOT NULL REFERENCES masking_policies(id) ON DELETE RESTRICT,
    policy_version          INTEGER NOT NULL,
    certificate_serial      VARCHAR(64) NOT NULL UNIQUE, -- e.g., SDB-2026-0004819
    frameworks              compliance_framework[] NOT NULL DEFAULT ARRAY['GDPR']::compliance_framework[],
    -- Canonical signed JSON document proving zero-leak execution, columns masked, row counts, and engine digest
    certificate_payload     JSONB NOT NULL,
    payload_sha256          CHAR(64) NOT NULL,
    -- Hash chain linking to the previous certificate in the same org (tamper-evident append-only log)
    previous_cert_hash      CHAR(64) NOT NULL,
    -- Ed25519 or KMS asymmetric signature over (previous_cert_hash || payload_sha256)
    signature_algorithm     VARCHAR(32) NOT NULL DEFAULT 'ED25519',
    signature_base64        TEXT NOT NULL,
    signing_key_id          VARCHAR(128) NOT NULL,
    pdf_storage_uri         VARCHAR(512), -- Optional object store URI for rendered PDF certificate
    issued_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_certs_org_issued ON audit_certificates (org_id, issued_at DESC);

-- Prevent accidental UPDATE/DELETE on audit_certificates (Immutability Enforcement)
CREATE OR REPLACE FUNCTION enforce_audit_certificate_immutability()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_certificates is an append-only compliance ledger and cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_certificates_immutable
    BEFORE UPDATE OR DELETE ON audit_certificates
    FOR EACH ROW EXECUTE FUNCTION enforce_audit_certificate_immutability();
