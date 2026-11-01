-- Flyway Migration: V6__api_endpoint_intelligence_and_spec_evolution.sql
-- Description: Schema extensions for Phase 6.5 API Endpoint Intelligence, Observation History & Specification Evolution

-- 1. Add revision_number to api_specifications to track specification evolution
ALTER TABLE security_data.api_specifications 
    ADD COLUMN IF NOT EXISTS revision_number INT NOT NULL DEFAULT 1;

-- 2. Index for specification revision history queries by specification name and import order
CREATE INDEX IF NOT EXISTS api_specs_name_imported_idx 
    ON security_data.api_specifications(name, imported_at DESC);

-- 3. Composite index on api_events for fast endpoint observation history queries
CREATE INDEX IF NOT EXISTS api_events_history_idx 
    ON security_data.api_events(http_method, route_id, timestamp DESC);

-- 4. Composite index on api_events for status code aggregation in observation history
CREATE INDEX IF NOT EXISTS api_events_status_history_idx 
    ON security_data.api_events(route_id, status_code, timestamp DESC);
