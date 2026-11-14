-- Migration: V8__exfiltration_campaigns.sql
-- Description: Multi-stage API exfiltration campaign detection tables for Phase 7.2.4.5

-- 1. Exfiltration Campaigns table
CREATE TABLE IF NOT EXISTS security_data.exfiltration_campaigns (
    id UUID PRIMARY KEY,
    campaign_id VARCHAR(64) NOT NULL UNIQUE,
    correlation_identity VARCHAR(128) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL DEFAULT 'DEFAULT_TENANT',
    client_ip VARCHAR(45) NOT NULL,
    current_stage VARCHAR(64) NOT NULL,
    stages_observed VARCHAR(512) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
    severity VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
    risk_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    risk_category VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
    risk_rationale TEXT NOT NULL,
    evidence_completeness VARCHAR(32) NOT NULL DEFAULT 'COMPLETE',
    missing_evidence_details TEXT,
    resource_count INT NOT NULL DEFAULT 0,
    endpoint_count INT NOT NULL DEFAULT 0,
    sensitive_domain_count INT NOT NULL DEFAULT 0,
    first_observed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_observed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    event_count INT NOT NULL DEFAULT 1,
    related_event_ids TEXT NOT NULL,
    related_incident_ids TEXT NOT NULL,
    related_rule_ids TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS exfil_campaigns_status_idx 
    ON security_data.exfiltration_campaigns(status);

CREATE INDEX IF NOT EXISTS exfil_campaigns_identity_idx 
    ON security_data.exfiltration_campaigns(correlation_identity);

CREATE INDEX IF NOT EXISTS exfil_campaigns_stage_idx 
    ON security_data.exfiltration_campaigns(current_stage);

CREATE INDEX IF NOT EXISTS exfil_campaigns_observed_idx 
    ON security_data.exfiltration_campaigns(last_observed_at DESC);

-- 2. Campaign Timeline Events table
CREATE TABLE IF NOT EXISTS security_data.campaign_events (
    id UUID PRIMARY KEY,
    campaign_id UUID NOT NULL REFERENCES security_data.exfiltration_campaigns(id) ON DELETE CASCADE,
    stage VARCHAR(64) NOT NULL,
    event_id UUID NOT NULL,
    rule_id VARCHAR(64) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    http_method VARCHAR(10) NOT NULL,
    request_path VARCHAR(512) NOT NULL,
    status_code INT NOT NULL,
    description VARCHAR(512) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS campaign_events_camp_idx 
    ON security_data.campaign_events(campaign_id);

CREATE INDEX IF NOT EXISTS campaign_events_ts_idx 
    ON security_data.campaign_events(timestamp DESC);

-- 3. Campaign Status History table (Audit Trail)
CREATE TABLE IF NOT EXISTS security_data.campaign_status_history (
    id UUID PRIMARY KEY,
    campaign_id UUID NOT NULL REFERENCES security_data.exfiltration_campaigns(id) ON DELETE CASCADE,
    previous_status VARCHAR(32) NOT NULL,
    new_status VARCHAR(32) NOT NULL,
    changed_by VARCHAR(128) NOT NULL,
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    reason VARCHAR(512)
);

CREATE INDEX IF NOT EXISTS campaign_status_history_camp_idx 
    ON security_data.campaign_status_history(campaign_id);

