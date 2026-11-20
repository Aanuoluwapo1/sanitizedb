-- =============================================================================
-- Mock Production Source Database (CONTAINS SYNTHETIC "DIRTY" PII FOR LOCAL DEV)
-- Demonstrates FK referential integrity across users -> orders -> audit_logs
-- and users -> payment_methods.
-- =============================================================================

CREATE TABLE users (
    id              BIGSERIAL PRIMARY KEY,
    external_uid    UUID NOT NULL UNIQUE,
    full_name       VARCHAR(160) NOT NULL,
    email           VARCHAR(255) NOT NULL UNIQUE,
    phone_number    VARCHAR(32) NOT NULL,
    national_id     VARCHAR(32) NOT NULL, -- SSN / NIN style sensitive identifier
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
    card_number         VARCHAR(32) NOT NULL, -- Raw PAN (PCI-DSS sensitive)
    billing_email       VARCHAR(255) NOT NULL,
    billing_zip         VARCHAR(16) NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE orders (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES users(id),
    customer_email      VARCHAR(255) NOT NULL, -- Denormalized email: must match users.email deterministically!
    shipping_address    TEXT NOT NULL,
    amount_cents        INTEGER NOT NULL,
    currency            CHAR(3) NOT NULL DEFAULT 'USD',
    status              VARCHAR(32) NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_logs (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             BIGINT REFERENCES users(id),
    actor_email         VARCHAR(255) NOT NULL, -- Denormalized email: must match users.email deterministically!
    ip_address          VARCHAR(45) NOT NULL,
    action              VARCHAR(64) NOT NULL,
    user_agent          TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed dirty production-like PII rows
INSERT INTO users (id, external_uid, full_name, email, phone_number, national_id, date_of_birth, signup_ip, country_code, tier) VALUES
(1, '11111111-1111-4111-8111-111111111101', 'Adaeze Okafor',    'adaeze.okafor@finbank-corp.ng',  '+234-803-555-0192', 'NIN-94827163541', '1991-04-12', '102.89.34.18',  'NG', 'ENTERPRISE'),
(2, '11111111-1111-4111-8111-111111111102', 'Marcus Vance',     'm.vance@healthtech.io',          '+1-415-555-0148',   '412-88-9021',     '1985-09-28', '198.51.100.42', 'US', 'PRO'),
(3, '11111111-1111-4111-8111-111111111103', 'Elena Rostova',    'elena.rostova@nordicpay.eu',     '+46-70-555-0183',   '19880315-4821',   '1988-03-15', '203.0.113.77',  'SE', 'ENTERPRISE'),
(4, '11111111-1111-4111-8111-111111111104', 'Chukwuemeka Eze',  'c.eze@lagoslogistics.com',       '+234-809-555-0137', 'NIN-77261904823', '1994-11-03', '102.89.41.209', 'NG', 'PRO'),
(5, '11111111-1111-4111-8111-111111111105', 'Sophia Lindqvist', 'sophia.l@cloudclinic.de',        '+49-151-5550194',   'DE-8492017462',   '1990-07-19', '192.0.2.154',   'DE', 'FREE');

SELECT setval('users_id_seq', (SELECT MAX(id) FROM users));

INSERT INTO payment_methods (user_id, cardholder_name, card_number, billing_email, billing_zip) VALUES
(1, 'Adaeze Okafor',    '4532-0151-1283-0366', 'adaeze.okafor@finbank-corp.ng', '100001'),
(2, 'Marcus Vance',     '5425-2334-3010-9903', 'm.vance@healthtech.io',         '94107'),
(3, 'Elena Rostova',    '4916-3892-7410-2281', 'elena.rostova@nordicpay.eu',    '11122'),
(4, 'Chukwuemeka Eze',  '5105-1051-0510-5100', 'c.eze@lagoslogistics.com',      '101233');

INSERT INTO orders (user_id, customer_email, shipping_address, amount_cents, currency, status) VALUES
(1, 'adaeze.okafor@finbank-corp.ng', '14 Adeola Odeku St, Victoria Island, Lagos', 49900,  'USD', 'PAID'),
(1, 'adaeze.okafor@finbank-corp.ng', '14 Adeola Odeku St, Victoria Island, Lagos', 12900,  'USD', 'SHIPPED'),
(2, 'm.vance@healthtech.io',         '742 Evergreen Terrace, San Francisco, CA',   89000,  'USD', 'PAID'),
(3, 'elena.rostova@nordicpay.eu',    'Kungsgatan 44, Stockholm',                   145000, 'EUR', 'PAID'),
(4, 'c.eze@lagoslogistics.com',      '22 Admiralty Way, Lekki Phase 1, Lagos',     27500,  'USD', 'PENDING'),
(5, 'sophia.l@cloudclinic.de',       'Friedrichstrasse 112, Berlin',               4900,   'EUR', 'PAID');

INSERT INTO audit_logs (user_id, actor_email, ip_address, action, user_agent) VALUES
(1, 'adaeze.okafor@finbank-corp.ng', '102.89.34.18',  'LOGIN_SUCCESS',      'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)'),
(1, 'adaeze.okafor@finbank-corp.ng', '102.89.34.18',  'EXPORT_INVOICE',     'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)'),
(2, 'm.vance@healthtech.io',         '198.51.100.42', 'UPDATE_BILLING',     'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
(3, 'elena.rostova@nordicpay.eu',    '203.0.113.77',  'CREATE_API_TOKEN',   'Mozilla/5.0 (X11; Linux x86_64)'),
(4, 'c.eze@lagoslogistics.com',      '102.89.41.209', 'LOGIN_SUCCESS',      'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4)');
