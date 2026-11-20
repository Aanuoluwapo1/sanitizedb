# SanitizeDB — Zero-Leak Staging Data Anonymizer & Synthetic Seeder

SanitizeDB is a commercial B2B SaaS and self-hosted enterprise platform that streams production-like, referentially intact, GDPR/NDPR/HIPAA/PCI-DSS compliant data into staging and QA databases **without ever persisting unmasked PII to disk**.

## System Architecture & Network Segmentation

```mermaid
flowchart LR
    subgraph ClientPlane["Client & CI/CD Plane"]
        UI["React + TypeScript Web Console<br/>(React Flow ER Mapper + Live Preview)"]
        CI["DevOps CI/CD<br/>(sanitizedb run --config policy.yaml)"]
    end

    subgraph ControlPlane["Control Plane Network (Zero access to Prod DB)"]
        ORCH["Go Orchestrator & WS Hub<br/>(Job Scheduler, Vault Client, gRPC Client)"]
        GOV["Java 21 / Spring Boot Governance Core<br/>(RBAC, Schema Drift Gate, Signed Certificates)"]
        CPDB[("Control Plane PostgreSQL<br/>orgs, connections, policies, jobs, audit_certificates")]
        VAULT["HashiCorp Vault / KMS<br/>(Dynamic DB Creds & Key Wrapping)"]
    end

    subgraph DataPlane["Isolated Data Plane Network (read_only rootfs, zero disk writes)"]
        RUST["Rust Stream Engine<br/>(tokio-postgres COPY, HMAC-SHA256 + fake-rs, bounded mpsc)"]
        SRC[("Source Prod DB (Read-Only)<br/>Raw PII")]
        TGT[("Target Staging DB<br/>Sanitized & FK-Intact")]
    end

    UI -->|"REST + WebSocket Telemetry"| ORCH
    UI -->|"Policy CRUD & RBAC"| GOV
    CI -->|"gRPC / Ephemeral CLI"| ORCH
    ORCH -->|"1. Drift & Policy Pre-Flight"| GOV
    ORCH -->|"2. Fetch Ephemeral DSN Lease"| VAULT
    GOV --> CPDB
    ORCH -->|"3. mTLS gRPC: Policy + Ephemeral Salt + DSNs"| RUST
    RUST -->|"4. COPY OUT (Read-Only Stream)"| SRC
    RUST -->|"5. In-Memory Bounded mpsc Transform -> COPY IN"| TGT
    RUST -.->|"6. Server-Streamed Progress + RunAttestation"| ORCH
    ORCH -->|"7. Mint Ed25519 Signed Certificate"| GOV
```

## Quick Start (Local Development)

```bash
# Boot mock dirty production Postgres (5433), empty staging Postgres (5434),
# control-plane Postgres (5432), Vault dev (8200), and all polyglot services:
docker compose up --build
```

- **Web Console**: http://localhost:5173
- **Go Orchestrator**: http://localhost:8080 (`GET /ws/jobs/{jobId}`)
- **Java Governance Core**: http://localhost:8081
- **Rust Stream Engine (gRPC)**: `localhost:50051`
- **Mock Source DB (dirty PII)**: `postgres://prod_readonly:prod_dev_password_only@localhost:5433/prod_app`
- **Mock Target Staging DB (empty)**: `postgres://staging_writer:staging_dev_password_only@localhost:5434/staging_app`
