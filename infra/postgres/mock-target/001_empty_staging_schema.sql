-- =============================================================================
-- Mock Target Staging Database (EMPTY SCHEMA READY FOR SANITIZED STREAMING)
-- Mirrors mock-source schema constraints so FK integrity is strictly validated
-- as SanitizeDB streams masked rows via PostgreSQL COPY IN.
-- =============================================================================

CREATE TABLE users (
    id              BIGSERIAL PRIMARY KEY,
    external_uid    UUID NOT NULL UNIQUE,
    full_name       VARCHAR(160) NOT NULL,
    email           VARCHAR(255) NOT NULL UNIQUE,
    phone_number    VARCHAR(32) NOT NULL,
    national_id     VARCHAR(32) NOT NULL,
    date_of_birth   DATE NOT NULL,
    signup_ip       VARCHAR(45) NOT NULL,
    country_code    CHAR(2) NOT NULL,
    tier            VARCHAR(20) NOT NULL DEFAULT 'FREE',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE payment_methods (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES users(id),
    cardholder_name     VARCHAR(160) NOT NULL,
    card_number         VARCHAR(32) NOT NULL,
    billing_email       VARCHAR(255) NOT NULL,
    billing_zip         VARCHAR(16) NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE orders (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES users(id),
    customer_email      VARCHAR(255) NOT NULL,
    shipping_address    TEXT NOT NULL,
    amount_cents        INTEGER NOT NULL,
    currency            CHAR(3) NOT NULL DEFAULT 'USD',
    status              VARCHAR(32) NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_logs (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             BIGINT REFERENCES users(id),
    actor_email         VARCHAR(255) NOT NULL,
    ip_address          VARCHAR(45) NOT NULL,
    action              VARCHAR(64) NOT NULL,
    user_agent          TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
