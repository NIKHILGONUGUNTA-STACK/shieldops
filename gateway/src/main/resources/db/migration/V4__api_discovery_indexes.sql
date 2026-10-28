-- Flyway Migration: V4__api_discovery_indexes.sql
-- Description: Indexes and column adjustments for Phase 6.1 Telemetry-Based API Discovery

-- 1. Ensure route_id can hold full normalized route templates
ALTER TABLE security_data.api_events 
    ALTER COLUMN route_id TYPE VARCHAR(256);

-- 2. Composite index for endpoint grouping, counting, and discovery queries
CREATE INDEX IF NOT EXISTS api_events_discovery_method_route_idx 
    ON security_data.api_events(http_method, route_id);

-- 3. Composite index for time-windowed discovery queries
CREATE INDEX IF NOT EXISTS api_events_discovery_route_time_idx 
    ON security_data.api_events(route_id, timestamp DESC);
