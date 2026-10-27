-- Flyway Migration: V3__soc_dashboard_indexes.sql
-- Description: Indexes optimizing Security Operations Center (SOC) dashboard queries

-- 1. Indexes for Incident Listing, Filtering, and Sorting
CREATE INDEX IF NOT EXISTS incidents_created_at_idx 
    ON security_data.incidents(created_at DESC);

CREATE INDEX IF NOT EXISTS incidents_last_event_at_idx 
    ON security_data.incidents(last_event_at DESC);

CREATE INDEX IF NOT EXISTS incidents_severity_status_idx 
    ON security_data.incidents(severity, status);

CREATE INDEX IF NOT EXISTS incidents_category_idx 
    ON security_data.incidents(threat_category);

-- 2. Indexes for Event Search by Anomaly Flag and Source IP
CREATE INDEX IF NOT EXISTS api_events_anomaly_flags_idx 
    ON security_data.api_events(anomaly_flags);

CREATE INDEX IF NOT EXISTS api_events_source_ip_idx 
    ON security_data.api_events(source_ip);

-- 3. Index for Overview Time-Bucket Aggregations
CREATE INDEX IF NOT EXISTS api_events_time_status_idx 
    ON security_data.api_events(timestamp DESC, status_code);

-- 4. Index for Global Policy Decisions Listing
CREATE INDEX IF NOT EXISTS policy_decisions_created_at_idx 
    ON security_data.policy_decisions(created_at DESC);
