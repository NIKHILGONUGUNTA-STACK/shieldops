-- Migration: V2__detection_telemetry.sql
-- Description: Add telemetry context fields and incident management tables for Phase 4 threat detection

-- 1. Extend api_events with resource context and error categories
ALTER TABLE security_data.api_events ADD COLUMN IF NOT EXISTS resource_type VARCHAR(64);
ALTER TABLE security_data.api_events ADD COLUMN IF NOT EXISTS resource_id VARCHAR(128);
ALTER TABLE security_data.api_events ADD COLUMN IF NOT EXISTS error_code VARCHAR(64);
ALTER TABLE security_data.api_events ADD COLUMN IF NOT EXISTS response_size_bytes BIGINT NOT NULL DEFAULT 0;
ALTER TABLE security_data.api_events ADD COLUMN IF NOT EXISTS record_count INT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS api_events_resource_idx 
    ON security_data.api_events(resource_type, resource_id);

CREATE INDEX IF NOT EXISTS api_events_error_code_idx 
    ON security_data.api_events(error_code);

-- 2. Security Incidents table
CREATE TABLE IF NOT EXISTS security_data.incidents (
    id UUID PRIMARY KEY,
    incident_fingerprint VARCHAR(128) NOT NULL UNIQUE,
    rule_id VARCHAR(64) NOT NULL,
    rule_version VARCHAR(32) NOT NULL,
    threat_category VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    target_entity_type VARCHAR(32) NOT NULL,
    target_entity_value VARCHAR(128) NOT NULL,
    first_detected_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_event_at TIMESTAMP WITH TIME ZONE NOT NULL,
    event_count INT NOT NULL DEFAULT 1,
    summary VARCHAR(512) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS incidents_status_idx 
    ON security_data.incidents(status);

CREATE INDEX IF NOT EXISTS incidents_entity_idx 
    ON security_data.incidents(target_entity_type, target_entity_value);

CREATE INDEX IF NOT EXISTS incidents_fingerprint_idx 
    ON security_data.incidents(incident_fingerprint);

-- 3. Detection Evidence table
CREATE TABLE IF NOT EXISTS security_data.detection_evidence (
    id UUID PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES security_data.incidents(id) ON DELETE CASCADE,
    rule_id VARCHAR(64) NOT NULL,
    rule_version VARCHAR(32) NOT NULL,
    evaluated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    confidence_score DOUBLE PRECISION NOT NULL,
    severity VARCHAR(32) NOT NULL,
    trigger_condition VARCHAR(256) NOT NULL,
    observed_count INT NOT NULL,
    window_seconds INT NOT NULL,
    distinct_resources INT NOT NULL,
    evidence_details TEXT,
    contributing_event_ids TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS evidence_incident_idx 
    ON security_data.detection_evidence(incident_id);

-- 4. Incident Status History table (Audit Trail)
CREATE TABLE IF NOT EXISTS security_data.incident_status_history (
    id UUID PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES security_data.incidents(id) ON DELETE CASCADE,
    previous_status VARCHAR(32) NOT NULL,
    new_status VARCHAR(32) NOT NULL,
    changed_by VARCHAR(128) NOT NULL,
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    reason VARCHAR(512)
);

CREATE INDEX IF NOT EXISTS status_history_incident_idx 
    ON security_data.incident_status_history(incident_id);

-- 5. Policy Decisions table (Strictly ADVISORY in Phase 4)
CREATE TABLE IF NOT EXISTS security_data.policy_decisions (
    id UUID PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES security_data.incidents(id) ON DELETE CASCADE,
    policy_rule VARCHAR(64) NOT NULL,
    recommended_action VARCHAR(64) NOT NULL,
    enforcement_level VARCHAR(32) NOT NULL DEFAULT 'ADVISORY',
    decided_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    rationale VARCHAR(512),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS policy_decisions_incident_idx 
    ON security_data.policy_decisions(incident_id);
