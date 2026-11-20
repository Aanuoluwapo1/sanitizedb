-- =============================================================================
-- SanitizeDB Local Development Seed (Idempotent)
-- Seeds default organization, source/target connections, and active masking policy
-- =============================================================================

INSERT INTO organizations (id, slug, name, plan, kms_key_alias, strict_drift_gate)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'acme-dev',
    'Acme Corp (Local Dev)',
    'ENTERPRISE',
    'vault://transit/keys/acme-dev',
    TRUE
) ON CONFLICT (id) DO NOTHING;

INSERT INTO connections (
    id, org_id, name, engine, role, host, port, database_name, ssl_mode,
    vault_secret_path, read_only_enforced, created_by
) VALUES (
    '00000000-0000-0000-0000-000000000010',
    '00000000-0000-0000-0000-000000000001',
    'prod_app',
    'POSTGRESQL',
    'SOURCE_PROD',
    'source-db',
    5432,
    'prod_app',
    'disable',
    'secret/data/sanitizedb/source-db',
    TRUE,
    'system-bootstrap'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO connections (
    id, org_id, name, engine, role, host, port, database_name, ssl_mode,
    vault_secret_path, read_only_enforced, created_by
) VALUES (
    '00000000-0000-0000-0000-000000000020',
    '00000000-0000-0000-0000-000000000001',
    'staging_app',
    'POSTGRESQL',
    'TARGET_STAGING',
    'target-db',
    5432,
    'staging_app',
    'disable',
    'secret/data/sanitizedb/target-db',
    FALSE,
    'system-bootstrap'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO masking_policies (
    id, org_id, source_connection_id, name, version, status, frameworks,
    rules_json, schema_baseline_json, rules_sha256, approved_by, approved_at, created_by
) VALUES (
    '00000000-0000-0000-0000-000000000100',
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000010',
    'prod-to-staging-gdpr-v1',
    1,
    'ACTIVE',
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
) ON CONFLICT (id) DO NOTHING;
