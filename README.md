# SanitizeDB — Zero-Leak Staging Data Anonymizer & Synthetic Seeder

**SanitizeDB** is an enterprise polyglot B2B SaaS and self-hosted data-privacy platform (**Rust + Go + Java 21 / Spring Boot 3.3 + React 18 / TypeScript / React Flow**) that streams production-like, referentially intact, **GDPR / NDPR / HIPAA / PCI-DSS** compliant data from production databases into staging and QA environments **without ever persisting unmasked PII to disk**.

---

## 1. The Problem & Core Guarantees

Engineering teams need realistic, production-shaped data in staging and QA environments to catch edge-case bugs, validate migrations, and benchmark query plans. However:
1. **Raw Production Dumps Violate Privacy Regulations**: Copying production snapshots (`pg_dump`, EBS snapshots) into lower environments leaks regulated PII/PHI/PAN data and violates GDPR, NDPR, HIPAA, and PCI-DSS.
2. **Naive Random Masking Breaks Foreign Keys & Joins**: Randomly replacing emails, names, or identifiers per table breaks denormalized joins (`users.email = orders.customer_email = audit_logs.actor_email`).
3. **Silent Production Schema Drift Leaks New PII Columns**: When product teams ship a new column (`ALTER TABLE users ADD COLUMN backup_phone VARCHAR(32)`), static masking scripts silently pass it through or break.

**SanitizeDB** solves all three problems through four architectural invariants:
- **Zero-Disk-Leak Data Plane**: The Rust `stream-engine` worker runs inside an isolated container with `read_only: true` root filesystem and zero writable volume mounts. Unmasked rows exist only transiently inside fixed-capacity RAM buffers (`tokio::sync::mpsc`) bridging PostgreSQL `COPY TO STDOUT` and `COPY FROM STDIN`.
- **Cross-Table Deterministic Referential Integrity**: Columns sharing a `deterministic_domain` (e.g., `identity.email` or `identity.full_name`) derive a domain-separated HMAC-SHA256 seed using an ephemeral per-job CSPRNG salt held in `Zeroizing<Vec<u8>>` memory.
- **Automated Schema-Drift & Fail-Closed PII Gate**: Before a single target table is truncated, SanitizeDB compares live `source-db` `information_schema.columns` against the approved masking policy, classifies unmapped columns into `HIGH` / `MEDIUM` / `LOW` PII risk, and fails closed (`BLOCKED_DRIFT`) if any unmapped `HIGH`-risk PII column is present.
- **Tamper-Evident Ed25519 Compliance Ledger**: Every completed run mints an immutable, hash-chained, Ed25519-signed `AuditCertificate` in PostgreSQL recording the SHA-256 salt commitment, policy digest, per-table row counts, and zero-disk-write attestation.

---

## 2. System Architecture & Defense-in-Depth Network Segmentation

SanitizeDB enforces strict network isolation between the **Control Plane** (`control-net`) and the **Data Plane** (`data-plane-net`). Neither the Java Governance Core nor the React Web Console even has a network route to `source-db`.

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              Client & CI/CD Plane                                      │
│                                                                                        │
│  • React 18 + TypeScript + React Flow Web Console (:5173)                              │
│    Interactive ER schema mapper, PII confidence badges, live 10-row preview,           │
│    Schema-Drift Quick-Map banner, WebSocket telemetry bar, Runs & Certificates drawer  │
│  • Standalone DevOps Cobra CLI (`sanitizedb run --config policy.yaml`)                 │
└──────────────────────┬───────────────────────────────────────────┬─────────────────────┘
                       │ REST + WebSocket (/ws/jobs/{jobId})       │ Policy CRUD & Drift API
                       ▼                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                  Control Plane Network (`control-net` — No Route to Prod DB)           │
│                                                                                        │
│  ┌───────────────────────────────────────┐   ┌──────────────────────────────────────┐  │
│  │ Go 1.23 Orchestrator (:8080)          │   │ Java 21 / Spring Boot 3.3 (:8081)    │  │
│  │ • CSPRNG 256-bit ephemeral job salt   │──►│ Governance Core                      │  │
│  │ • Vault / KMS secret resolution       │   │ • Versioned JSONB MaskingPolicy      │  │
│  │ • Bounded-replay WebSocket hub        │   │ • Automated Schema-Drift Inspector   │  │
│  │ • Exponential-backoff governance sync │   │ • Ed25519 Hash-Chained Certificates  │  │
│  └───────────────────┬───────────────────┘   └──────────────────┬───────────────────┘  │
│                      │                                          │                      │
│                      │                       ┌──────────────────▼───────────────────┐  │
│                      │                       │ Control-Plane PostgreSQL 16 (:5432)  │  │
│                      │                       │ organizations, connections,          │  │
│                      │                       │ masking_policies, sync_jobs,         │  │
│                      │                       │ audit_certificates (append-only)     │  │
│                      │                       └──────────────────────────────────────┘  │
└──────────────────────┼─────────────────────────────────────────────────────────────────┘
                       │ mTLS / gRPC (`StreamEngineService` on :50051)
                       │ Ephemeral DSNs + Ephemeral 32-Byte Salt + TablePolicies
                       ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│         Isolated Data Plane Network (`data-plane-net` — `read_only: true` rootfs)      │
│                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │ Rust Stream Engine (`services/stream-engine`, :50051)                            │  │
│  │ 1. Fail-closed schema & unmapped HIGH-risk PII validation (`information_schema`) │  │
│  │ 2. Transactional reverse-FK target reset (`TRUNCATE ... RESTART IDENTITY`)       │  │
│  │ 3. `COPY table TO STDOUT` ──► Bounded `mpsc` RAM Masker ──► `COPY table FROM STDIN`│ │
│  │ 4. `Zeroizing<Vec<u8>>` scrubs ephemeral salt from RAM on job exit               │  │
│  └───────────────────┬──────────────────────────────────────────┬───────────────────┘  │
│                      │ Read-Only Stream                         │ Sanitized COPY IN    │
│                      ▼                                          ▼                      │
│  ┌───────────────────────────────────────┐   ┌──────────────────────────────────────┐  │
│  │ Source Production DB (:5433)          │   │ Target Staging DB (:5434)            │  │
│  │ `prod_app` (Dirty PII + FK Graph)     │   │ `staging_app` (0 Leaked PII, FKs OK) │  │
│  └───────────────────────────────────────┘   └──────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### End-to-End Execution Sequence

```mermaid
sequenceDiagram
    autonumber
    participant UI as Web Console / CI CLI
    participant Orch as Go Orchestrator (:8080)
    participant Gov as Java Governance Core (:8081)
    participant Rust as Rust Stream Engine (:50051)
    participant Src as Source Prod DB (:5433)
    participant Tgt as Target Staging DB (:5434)

    UI->>Gov: GET /api/v1/governance/policies/active/drift
    Gov->>Orch: GET /api/v1/schema/inspect
    Orch->>Rust: gRPC InspectSchema(source_dsn)
    Rust->>Src: Query information_schema.columns
    Rust-->>Gov: Live columns + heuristic PII risk (HIGH / MEDIUM / LOW)
    Gov-->>UI: PolicyDriftInspectionReport (syncBlocked if unmapped HIGH PII)
    UI->>Orch: Trigger Sync (POST /api/v1/jobs or `sanitizedb run`)
    Orch->>Orch: Generate 256-bit CSPRNG ephemeral_job_salt in RAM
    Orch->>Rust: gRPC ExecuteSanitizationJob(DSNs, Policy, ephemeral_job_salt)
    Rust->>Src: Fail-closed column & unmapped HIGH-risk PII verification
    Rust->>Tgt: BEGIN; TRUNCATE child..parent RESTART IDENTITY CASCADE; COMMIT;
    par Streaming COPY Pipeline (RAM-only bounded mpsc)
        Rust->>Src: COPY table TO STDOUT (FORMAT text)
        Rust->>Rust: HMAC-SHA256(salt, domain || 0x00 || raw) -> fake-rs / PartialMask
        Rust->>Tgt: COPY table FROM STDIN (FORMAT text)
    and Real-Time Telemetry
        Rust-->>Orch: SyncProgressEvent (rows/sec, duration_ms, table progress)
        Orch-->>UI: WebSocket broadcast (/ws/jobs/{jobId})
    end
    Rust->>Rust: Zeroize ephemeral_job_salt on Drop
    Rust-->>Orch: RunAttestation (salt_commitment_sha256, zero_disk_writes_verified)
    Orch->>Gov: POST /api/v1/governance/runs
    Gov-->>Orch: Minted Ed25519 Hash-Chained AuditCertificate (SDB-2026-...)
```

---

## 3. Cryptographic & Systems Foundations

### 3.1 Domain-Separated Deterministic Masking (`HmacDeterministicMasker`)

To preserve foreign-key and denormalized join consistency across tables without persisting a lookup table to disk, the Rust engine derives a 256-bit deterministic PRNG seed $s \in \{0,1\}^{256}$ for each raw value $v_{\text{raw}}$ under column rule $r$:

$$s = \text{HMAC-SHA256}\Big(K_{\text{job}},\; \text{domain}(r) \;\|\; \texttt{0x00} \;\|\; \text{UTF8}(v_{\text{raw}})\Big)$$

where:
- $K_{\text{job}} \in \{0,1\}^{256}$ is an ephemeral CSPRNG key generated per sync job by the Go Orchestrator, held in Rust inside `zeroize::Zeroizing<Vec<u8>>`, and wiped from memory upon stream completion.
- $\text{domain}(r)$ is the shared semantic domain tag (e.g., `identity.email` across `users.email`, `payment_methods.billing_email`, `orders.customer_email`, and `audit_logs.actor_email`).
- The null-byte separator `\x00` prevents prefix-collision attacks between domain names and raw column values.
- $s$ seeds `rand::rngs::StdRng::from_seed(s)` to drive `fake-rs` generators (RFC-valid synthetic emails with deterministic collision-resistant hex tags, full names, phone numbers, Luhn-valid `4242` test credit card PANs, national IDs, street addresses, and dates of birth).
- Only the one-way commitment $C_{\text{salt}} = \text{SHA-256}(K_{\text{job}})$ is recorded in `sync_jobs` and `audit_certificates`, proving a high-entropy salt was used without ever revealing $K_{\text{job}}$.

### 3.2 Bounded Backpressure & Zero-Disk-Leak Streaming (`StreamingTableTransformer`)

Each table stream runs two concurrent tasks joined via `tokio::try_join!(producer, consumer)` over a bounded channel `tokio::sync::mpsc::channel::<Bytes>(B)` (default $B = 512$ batches):
1. **Producer**: Pulls raw tab-delimited chunks from `source.copy_out("COPY ... TO STDOUT (FORMAT text)")`, splits complete lines in a reusable heap buffer, transforms each column according to its `MaskingStrategy` (`DeterministicFake`, `PartialMask`, `Nullify`, `Shuffle`, `PassThrough`), and awaits `tx.send(...)` when the channel reaches capacity $B$.
2. **Consumer**: Drains masked byte batches from `rx.recv()` directly into `target.copy_in("COPY ... FROM STDIN (FORMAT text)")`.

Memory consumption is strictly bounded by $O(B \cdot \text{chunk\_size})$ regardless of whether a table has $10^3$ or $10^9$ rows.

### 3.3 Automated Schema-Drift & Unmapped PII Risk Classifier

During both proactive drift inspection (`GET /api/v1/governance/policies/active/drift`) and pre-flight sync validation (`validate_policy_and_schemas`), SanitizeDB compares live `source-db` columns against `MaskingPolicy.rulesJson` and classifies any unmapped column into three risk tiers:

| Risk Tier | Matched Column Patterns | Default Enforcement (`strictDriftBlock = true`) |
| :--- | :--- | :--- |
| **`HIGH`** | `email`, `phone`, `mobile`, `ssn`, `nin`, `bvn`, `passport`, `national_id`, `card`, `cvv`, `iban`, `account`, `address`, `ip`, `dob`, `birth`, `token`, `secret` | **Fails Closed (`BLOCKED_DRIFT`)** before target truncation; suggests `DETERMINISTIC_FAKE`, `PARTIAL_MASK`, or `NULLIFY`. |
| **`MEDIUM`** | `name`, `user`, `city`, `country`, `zip`, `postal` | Flagged in Web Console Drift Banner with one-click rule mapping. |
| **`LOW`** | All other columns | Flagged as low-risk schema drift; omitted from `COPY` stream until mapped. |

### 3.4 Tamper-Evident Hash-Chained Ed25519 Audit Certificates

Upon every verified zero-disk-leak completion, `RunGovernanceService` constructs a canonical certificate payload $\mathcal{P}_i$, computes its digest $H_i = \text{SHA-256}(\mathcal{P}_i)$, links it to the organization's previous certificate hash $H_{i-1}$ (or $0^{64}$ for the genesis certificate), and signs the chain transition with JDK 21 `Ed25519`:

$$\sigma_i = \text{Ed25519.Sign}_{sk}\Big(\text{ASCII}(H_{i-1} \;\|\; \text{":"} \;\|\; H_i)\Big)$$

In PostgreSQL (`001_init_schema.sql`), the `audit_certificates` table is guarded by a `BEFORE UPDATE OR DELETE` trigger (`trg_audit_certificates_immutable`) that raises an exception on any mutation attempt.

---

## 4. Monorepo Directory Structure

```text
sanitizedb/
├── docker-compose.yml                         # 8-container topology (data-plane-net + control-net)
├── Makefile                                   # up, down, proto-gen, test-rust, test-go, test-java
├── README.md
├── infra/
│   └── postgres/
│       ├── control-plane/
│       │   ├── 001_init_schema.sql            # organizations, connections, masking_policies, sync_jobs, audit_certificates
│       │   └── 002_dev_seed.sql               # Idempotent local tenant, connections, and active 4-table GDPR/NDPR policy
│       ├── mock-source/
│       │   └── 001_dirty_pii_seed.sql         # Dirty production seed (users, payment_methods, orders, audit_logs)
│       └── mock-target/
│           └── 001_empty_staging_schema.sql   # Empty staging schema with matching PK/FK constraints
├── packages/
│   └── proto/
│       ├── buf.yaml
│       ├── buf.gen.yaml
│       └── sanitizedb/v1/
│           └── stream_engine.proto            # gRPC contract: InspectSchema, PreviewMasking, ExecuteSanitizationJob
├── services/
│   ├── stream-engine/                         # Rust (tokio, tokio-postgres, tonic, hmac, sha2, fake, zeroize, regex)
│   │   ├── Cargo.toml
│   │   ├── Dockerfile                         # Multi-stage build -> non-root debian:bookworm-slim (read_only rootfs)
│   │   ├── build.rs
│   │   └── src/
│   │       ├── main.rs                        # tonic gRPC server: InspectSchema & ExecuteSanitizationJob streams
│   │       ├── masker.rs                      # DeterministicMasker trait, HmacDeterministicMasker, Luhn PAN generator
│   │       ├── detector.rs                    # Regex + heuristic HIGH/MEDIUM/LOW PII classifier & unit tests
│   │       └── pipeline.rs                    # Fail-closed drift validator, reverse-FK transactional truncate, mpsc COPY pipeline
│   ├── orchestrator-cli/                      # Go 1.23 (cobra, gorilla/websocket, grpc, yaml.v3)
│   │   ├── go.mod & go.sum
│   │   ├── Dockerfile
│   │   ├── cmd/sanitizedb/main.go             # `sanitizedb serve` (:8080 HTTP/WS API) & `sanitizedb run` (CI/CD CLI)
│   │   ├── examples/policy.yaml               # Declarative 4-table policy for CLI & CI/CD runs
│   │   ├── gen/sanitizedb/v1/                 # Buf-generated Go protobuf & gRPC client bindings
│   │   └── internal/
│   │       ├── config/policy.go               # YAML/JSON policy parser
│   │       ├── governance/client.go           # Retry/backoff HTTP client to Java Governance Core
│   │       ├── grpcclient/client.go           # Live gRPC adapter to Rust Stream Engine
│   │       ├── runner/job_runner.go           # CSPRNG salt lifecycle, secret resolution, drift gate, run reporting
│   │       └── ws/
│   │           ├── broadcaster.go             # Non-blocking WebSocket fan-out hub with bounded 256-job replay cache
│   │           └── broadcaster_test.go        # Unit tests for FIFO eviction & late-subscriber frame replay
│   └── governance-core/                       # Java 21 / Spring Boot 3.3 (Spring Data JPA, Security, PostgreSQL)
│       ├── pom.xml
│       ├── Dockerfile
│       └── src/main/
│           ├── resources/application.yml
│           └── java/com/sanitizedb/governance/
│               ├── GovernanceCoreApplication.java
│               ├── config/SecurityConfig.java
│               ├── controller/GovernanceController.java
│               ├── dto/
│               │   ├── RunRecordingDtos.java  # Drift reports, run summaries, policy update records
│               │   └── SchemaDriftDtos.java
│               ├── entity/
│               │   ├── MaskingPolicy.java     # Versioned JSONB policy entity
│               │   ├── SyncJob.java           # Execution ledger entity
│               │   └── AuditCertificate.java  # @Immutable Ed25519 hash-chained certificate entity
│               ├── repository/
│               │   ├── MaskingPolicyRepository.java
│               │   ├── SyncJobRepository.java
│               │   └── AuditCertificateRepository.java
│               └── service/
│                   ├── RunGovernanceService.java             # Drift inspection, run recording, Ed25519 certificate minting
│                   └── CompliancePolicyValidatorService.java # Regulatory policy validation
└── apps/
    └── web-console/                           # React 18 + TypeScript + Vite + Tailwind CSS + Zustand + React Flow
        ├── package.json
        ├── Dockerfile
        └── src/
            ├── App.tsx                        # Top control bar, live WS telemetry strip, React Flow ER canvas
            ├── types/schema.ts
            ├── store/useMapperStore.ts        # Live policy sync, drift quick-mapper, job trigger & WebSocket client
            └── components/
                ├── TableNode.tsx              # Custom React Flow node with PII badges, domain inputs & strategy selectors
                ├── SchemaDriftBanner.tsx      # Proactive drift alert banner & one-click Quick-Map controls
                ├── RunsAndCertificatesDrawer.tsx # Slide-over audit ledger for sync_jobs & Ed25519 certificates
                └── LivePreviewDrawer.tsx      # 10-row live anonymized sample preview drawer
```

---

## 5. Quick Start & End-to-End Verification

### 5.1 Boot the Full Polyglot Stack

```bash
docker compose up --build -d
```

| Service | Endpoint / Port | Description |
| :--- | :--- | :--- |
| **React Web Console** | `http://localhost:5173` | Visual ER Schema Mapper, Drift Quick-Map & Audit Certificates UI |
| **Go Orchestrator API & WS** | `http://localhost:8080` | `GET /healthz`, `GET /api/v1/schema/inspect`, `POST /api/v1/jobs`, `GET /ws/jobs/{jobId}` |
| **Java 21 Governance Core** | `http://localhost:8081` | `GET /api/v1/governance/policies/active`, `/drift`, `/runs`, `/certificates` |
| **Rust Stream Engine** | `localhost:50051` | gRPC `StreamEngineService` (`read_only: true` rootfs) |
| **Mock Source Prod DB** | `localhost:5433` (`prod_app`) | Pre-seeded with dirty PII across `users`, `payment_methods`, `orders`, `audit_logs` |
| **Mock Target Staging DB** | `localhost:5434` (`staging_app`) | Receives sanitized, FK-intact rows via `COPY FROM STDIN` |
| **Control Plane DB** | `localhost:5432` (`sanitizedb_control`) | Multi-tenant policies, sync job ledger, and append-only audit certificates |
| **HashiCorp Vault (Dev)** | `http://localhost:8200` | Ephemeral secret store & KMS (`VAULT_TOKEN=sanitizedb-dev-root-token`) |

### 5.2 Execute a Zero-Leak Streaming Sync via CLI

```bash
docker exec sanitizedb-orchestrator /usr/local/bin/sanitizedb run \
  --config /etc/sanitizedb/policy.yaml \
  --engine-addr stream-engine:50051 \
  --governance-url http://governance-core:8081
```

Sample output:
```text
SanitizeDB job d7ae6baf-b76f-4f04-affb-d92db9ad7fac completed cleanly via stream-engine:50051 (20 rows in 93ms, zero-disk-leak verified)
Salt Commitment (SHA-256): 6f899bbc2bf2db15aacc5cc5f35b1a88d95e8445921de2d0d5b6c3a749c4e866
Compliance Certificate:    SDB-2026-B7A3A7E1
  - public.users                  5 rows (0ms)
  - public.payment_methods        4 rows (0ms)
  - public.orders                 6 rows (0ms)
  - public.audit_logs             5 rows (0ms)
```

### 5.3 Verify Cross-Table Deterministic Joins in `target-db`

```bash
docker exec sanitizedb-target-db psql -U staging_writer -d staging_app \
  -c "SELECT u.id, u.full_name, u.email AS user_email, o.customer_email AS order_email, a.actor_email AS audit_email, (u.email = o.customer_email AND u.email = a.actor_email) AS deterministic_match FROM users u JOIN orders o ON o.user_id = u.id JOIN audit_logs a ON a.user_id = u.id ORDER BY u.id LIMIT 5;"
```

### 5.4 Test Proactive Schema-Drift Detection & Fail-Closed Blocking

```bash
# 1. Simulate a new unmapped HIGH-risk PII column added to production source-db
docker exec sanitizedb-source-db psql -U prod_readonly -d prod_app \
  -c "ALTER TABLE users ADD COLUMN IF NOT EXISTS backup_phone VARCHAR(32) DEFAULT '+234-802-555-0199';"

# 2. Query Governance Core drift inspection endpoint
#    -> Returns driftDetected: true, syncBlocked: true, highRiskCount: 1, riskLevel: "HIGH" (PHONE)
curl -s http://localhost:8081/api/v1/governance/policies/active/drift

# 3. Attempt a sync while backup_phone is unmapped
#    -> Fails closed with SCHEMA_DRIFT_BLOCKED before truncating target-db and logs status=BLOCKED_DRIFT
docker exec sanitizedb-orchestrator /usr/local/bin/sanitizedb run \
  --config /etc/sanitizedb/policy.yaml \
  --engine-addr stream-engine:50051 \
  --governance-url http://governance-core:8081

# 4. Open http://localhost:5173 and click "Add Rule & Save" in the Schema Drift banner
#    (or drop the test column to restore baseline):
docker exec sanitizedb-source-db psql -U prod_readonly -d prod_app \
  -c "ALTER TABLE users DROP COLUMN IF EXISTS backup_phone;"
```

### 5.5 Inspect Recorded Sync Jobs & Hash-Chained Certificates

```bash
docker exec sanitizedb-control-db psql -U sanitizedb -d sanitizedb_control \
  -c "SELECT id, status, trigger_source, schema_drift_detected AS drift, rows_processed, left(salt_commitment_sha256, 16) AS salt_sha256 FROM sync_jobs ORDER BY created_at DESC;" \
  -c "SELECT certificate_serial, sync_job_id, policy_version, signature_algorithm, left(previous_cert_hash, 16) AS prev_hash, left(payload_sha256, 16) AS payload_hash FROM audit_certificates ORDER BY issued_at ASC;"
```

---

## 6. REST, WebSocket & gRPC API Reference

### Governance Core (`http://localhost:8081`)
- `GET /api/v1/governance/healthz` — Service health probe.
- `GET /api/v1/governance/policies/active` — Returns the active `MaskingPolicy` and its JSONB table/column rules.
- `GET /api/v1/governance/policies/active/drift?strictDriftBlock=true` — Inspects live `source-db` columns via the data plane and returns `PolicyDriftInspectionReport` (`unmappedColumns`, `highRiskCount`, `syncBlocked`, `suggestedStrategy`).
- `PUT /api/v1/governance/policies/{policyId}/rules` — Updates column masking rules and recomputes `rules_sha256`.
- `POST /api/v1/governance/runs` — Records a `SUCCEEDED`, `FAILED`, or `BLOCKED_DRIFT` sync run and mints an `ED25519` `AuditCertificate` on verified completion.
- `GET /api/v1/governance/runs` — Lists recent sync jobs paired with their compliance certificates.
- `GET /api/v1/governance/certificates` — Lists issued hash-chained compliance certificates.

### Orchestrator (`http://localhost:8080`)
- `GET /healthz` — Liveness probe with connected gRPC and Governance endpoints.
- `GET /api/v1/schema/inspect` — Triggers a live zero-leak `InspectSchema` gRPC call against `source-db`.
- `POST /api/v1/jobs` — Enqueues an asynchronous zero-leak sync run and returns `{ "jobId": "...", "wsPath": "/ws/jobs/..." }`.
- `GET /ws/jobs/{jobId}` — WebSocket stream emitting real-time `ProgressEvent` frames (with automatic replay for fast-completing runs).
