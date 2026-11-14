-- ============================================================================
-- Flyway Migration V9: Adaptive Security Response & Policy Decision Engine
-- Phase 7.2.4.6: Context-Aware Advisory Policy Engine
-- ============================================================================

-- 1. Alter existing security_data.policy_decisions to support modern adaptive architecture
ALTER TABLE security_data.policy_decisions
    ALTER COLUMN incident_id DROP NOT NULL;

ALTER TABLE security_data.policy_decisions ADD COLUMN IF NOT EXISTS campaign_id UUID;
ALTER TABLE security_data.policy_decisions ADD COLUMN IF NOT EXISTS policy_id VARCHAR(64) NOT NULL DEFAULT 'POL-DEFAULT';
ALTER TABLE security_data.policy_decisions ADD COLUMN IF NOT EXISTS policy_version VARCHAR(32) NOT NULL DEFAULT '1.0.0';
ALTER TABLE security_data.policy_decisions ADD COLUMN IF NOT EXISTS category VARCHAR(64) NOT NULL DEFAULT 'GENERAL';
ALTER TABLE security_data.policy_decisions ADD COLUMN IF NOT EXISTS risk_level VARCHAR(32) NOT NULL DEFAULT 'MEDIUM';
ALTER TABLE security_data.policy_decisions ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'RECOMMENDED';
ALTER TABLE security_data.policy_decisions ADD COLUMN IF NOT EXISTS evidence_completeness VARCHAR(32) NOT NULL DEFAULT 'COMPLETE';
ALTER TABLE security_data.policy_decisions ADD COLUMN IF NOT EXISTS identity_context VARCHAR(255);
ALTER TABLE security_data.policy_decisions ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(100) DEFAULT 'tenant-default';
ALTER TABLE security_data.policy_decisions ADD COLUMN IF NOT EXISTS supporting_evidence TEXT;
ALTER TABLE security_data.policy_decisions ADD COLUMN IF NOT EXISTS evidence_snapshot TEXT;
ALTER TABLE security_data.policy_decisions ADD COLUMN IF NOT EXISTS analyst_user VARCHAR(128);
ALTER TABLE security_data.policy_decisions ADD COLUMN IF NOT EXISTS analyst_action VARCHAR(32);
ALTER TABLE security_data.policy_decisions ADD COLUMN IF NOT EXISTS analyst_rationale VARCHAR(1024);
ALTER TABLE security_data.policy_decisions ADD COLUMN IF NOT EXISTS analyst_action_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX IF NOT EXISTS idx_policy_decisions_campaign_id
    ON security_data.policy_decisions(campaign_id);

CREATE INDEX IF NOT EXISTS idx_policy_decisions_policy_id
    ON security_data.policy_decisions(policy_id);

CREATE INDEX IF NOT EXISTS idx_policy_decisions_status
    ON security_data.policy_decisions(status);

CREATE INDEX IF NOT EXISTS idx_policy_decisions_decided_at
    ON security_data.policy_decisions(decided_at DESC);

-- 2. Security Policy Definitions Table
CREATE TABLE IF NOT EXISTS security_data.security_policies (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(32) NOT NULL,
    category VARCHAR(64) NOT NULL,
    recommended_action VARCHAR(64) NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    risk_threshold NUMERIC(5,2) NOT NULL DEFAULT 40.0,
    condition_explanation TEXT,
    effective_from TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_security_policies_category
    ON security_data.security_policies(category);

-- 3. Policy Audit History Table (Tracks policy modifications & threshold tuning)
CREATE TABLE IF NOT EXISTS security_data.policy_audit_history (
    id UUID PRIMARY KEY,
    policy_id VARCHAR(64) NOT NULL,
    previous_version VARCHAR(32),
    new_version VARCHAR(32) NOT NULL,
    changed_by VARCHAR(128) NOT NULL,
    change_type VARCHAR(32) NOT NULL,
    change_reason VARCHAR(512),
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_policy_audit_history_policy_id
    ON security_data.policy_audit_history(policy_id, changed_at DESC);

-- 4. Policy Decision Actions Table (Tracks analyst approvals, rejections, comments)
CREATE TABLE IF NOT EXISTS security_data.policy_decision_actions (
    id UUID PRIMARY KEY,
    decision_id UUID NOT NULL REFERENCES security_data.policy_decisions(id) ON DELETE CASCADE,
    action VARCHAR(32) NOT NULL,
    analyst_user VARCHAR(128) NOT NULL,
    analyst_comment VARCHAR(1024) NOT NULL,
    action_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_decision_actions_decision_id
    ON security_data.policy_decision_actions(decision_id, action_at ASC);

-- 5. Seed Baseline Security Policies
INSERT INTO security_data.security_policies (
    id, name, version, category, recommended_action, description, enabled, risk_threshold, condition_explanation, effective_from, updated_at
) VALUES
(
    'POL-RECON-01',
    'Repeated Reconnaissance Probing Policy',
    '1.0.0',
    'RECONNAISSANCE',
    'MONITOR_ACTIVITY',
    'Recommends passive monitoring and heightened logging when unauthenticated probing or actuator traversal is detected.',
    TRUE,
    20.0,
    'Matched when repeated 404 scans on actuator, Swagger, or debug endpoints occur without authorization bypass.',
    NOW(),
    NOW()
),
(
    'POL-BOLA-PROBE-01',
    'Authorization Probing Verification Policy',
    '1.0.0',
    'AUTHORIZATION',
    'REVIEW_AUTHORIZATION',
    'Recommends auditing customer identity and token permissions when cross-owner resource access attempts are denied (HTTP 403).',
    TRUE,
    45.0,
    'Matched when an authenticated identity queries resources belonging to another tenant or customer resulting in 403 Forbidden.',
    NOW(),
    NOW()
),
(
    'POL-BOLA-CONFIRMED-01',
    'Confirmed Unauthorized Access Escalation Policy',
    '1.0.0',
    'AUTHORIZATION',
    'ESCALATE_INCIDENT',
    'Recommends immediate high-priority incident escalation when cross-owner data leakage is confirmed (HTTP 200 on cross-owner resource).',
    TRUE,
    85.0,
    'Matched when an authenticated identity successfully accesses a cross-owner customer or account entity.',
    NOW(),
    NOW()
),
(
    'POL-DATA-EXPOSURE-01',
    'Excessive Data Exposure & Schema Drift Policy',
    '1.0.0',
    'DATA_EXPOSURE',
    'REVIEW_DATA_EXPOSURE',
    'Recommends contract review and schema patching when response payloads leak undeclared CONFIDENTIAL or RESTRICTED fields.',
    TRUE,
    70.0,
    'Matched when backend responses return properties outside declared OpenAPI specification contracts.',
    NOW(),
    NOW()
),
(
    'POL-BULK-EXTRACT-01',
    'Rapid Bulk Extraction Investigation Policy',
    '1.0.0',
    'BULK_EXTRACTION',
    'INVESTIGATE_ACTIVITY',
    'Recommends SOC analyst triage when high-frequency harvesting or rapid pagination harvesting is identified.',
    TRUE,
    75.0,
    'Matched when >= 3 distinct sensitive resources or multiple consecutive pagination windows are retrieved rapidly.',
    NOW(),
    NOW()
),
(
    'POL-LOW-SLOW-01',
    'Low-and-Slow Extraction Tracking Policy',
    '1.0.0',
    'BULK_EXTRACTION',
    'INVESTIGATE_ACTIVITY',
    'Recommends temporal correlation analysis when creeping extraction occurs across extended sliding windows (600s).',
    TRUE,
    65.0,
    'Matched when a caller retrieves >= 5 distinct resources at sub-threshold query frequencies.',
    NOW(),
    NOW()
),
(
    'POL-MULTI-DOMAIN-01',
    'Multi-Domain Cross-Entity Extraction Policy',
    '1.0.0',
    'BULK_EXTRACTION',
    'INVESTIGATE_ACTIVITY',
    'Recommends enterprise threat evaluation when extraction spans multiple microservice boundaries (Customer, Account, Transfer).',
    TRUE,
    80.0,
    'Matched when an attacker enumerates across >= 2 independent entity domains within the correlation window.',
    NOW(),
    NOW()
),
(
    'POL-CAMPAIGN-01',
    'Multi-Stage Exfiltration Campaign Prioritization Policy',
    '1.0.0',
    'CAMPAIGN',
    'PRIORITIZE_CAMPAIGN',
    'Recommends top-priority SOC response and forensic correlation when multi-stage kill-chain progression is confirmed.',
    TRUE,
    85.0,
    'Matched when an attacker progresses through >= 2 distinct attack stages culminating in bulk or cross-domain extraction.',
    NOW(),
    NOW()
),
(
    'POL-AMBIGUOUS-EVIDENCE-01',
    'Incomplete or Ambiguous Evidence Policy',
    '1.0.0',
    'EVIDENCE_INTEGRITY',
    'REQUEST_ADDITIONAL_EVIDENCE',
    'Suppresses severe escalation and requests forensic telemetry enrichment when incident or campaign evidence is degraded or incomplete.',
    TRUE,
    30.0,
    'Matched when evidence completeness is marked INCOMPLETE or DEGRADED, or when ownership context cannot be determined.',
    NOW(),
    NOW()
);
