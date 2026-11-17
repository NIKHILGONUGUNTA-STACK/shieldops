-- ============================================================================
-- Flyway Migration V10: Enterprise SOC Runtime Operations & Observability
-- Phase 7.3.2: Attribution Telemetry, Simulation Persistence & Network Intelligence
-- ============================================================================

-- 1. Extend security_data.api_events with attribution, tenant, and service dimensions
ALTER TABLE security_data.api_events
    ADD COLUMN IF NOT EXISTS simulation_run_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS simulation_campaign_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS simulation_scenario_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) DEFAULT 'tenant-default',
    ADD COLUMN IF NOT EXISTS service_name VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_api_events_sim_run_id
    ON security_data.api_events(simulation_run_id);

CREATE INDEX IF NOT EXISTS idx_api_events_tenant_id
    ON security_data.api_events(tenant_id);

CREATE INDEX IF NOT EXISTS idx_api_events_ip_timestamp
    ON security_data.api_events(source_ip, "timestamp" DESC);

CREATE INDEX IF NOT EXISTS idx_api_events_subject_timestamp
    ON security_data.api_events(auth_subject, "timestamp" DESC);

CREATE INDEX IF NOT EXISTS idx_api_events_route_status_time
    ON security_data.api_events(route_id, status_code, "timestamp" DESC);

-- 2. Durable Simulation Run Persistence across Gateway restarts
CREATE TABLE IF NOT EXISTS security_data.simulation_runs (
    run_id VARCHAR(64) PRIMARY KEY,
    campaign_id VARCHAR(64),
    template_id VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    duration_seconds INT NOT NULL DEFAULT 60,
    request_rate DOUBLE PRECISION NOT NULL DEFAULT 10.0,
    concurrency INT NOT NULL DEFAULT 1,
    traffic_mix VARCHAR(32) NOT NULL DEFAULT 'SEQUENTIAL',
    dry_run BOOLEAN NOT NULL DEFAULT FALSE,
    deterministic_seed BIGINT,
    total_requests INT NOT NULL DEFAULT 0,
    requests_2xx INT NOT NULL DEFAULT 0,
    requests_4xx INT NOT NULL DEFAULT 0,
    requests_5xx INT NOT NULL DEFAULT 0,
    all_passed BOOLEAN NOT NULL DEFAULT FALSE,
    provenance_json TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sim_runs_status
    ON security_data.simulation_runs(status);

CREATE INDEX IF NOT EXISTS idx_sim_runs_template
    ON security_data.simulation_runs(template_id);

CREATE INDEX IF NOT EXISTS idx_sim_runs_start_time
    ON security_data.simulation_runs(start_time DESC);

-- 3. Stage-level execution assertions and results
CREATE TABLE IF NOT EXISTS security_data.simulation_run_stages (
    id UUID PRIMARY KEY,
    run_id VARCHAR(64) NOT NULL REFERENCES security_data.simulation_runs(run_id) ON DELETE CASCADE,
    stage_id VARCHAR(64) NOT NULL,
    stage_name VARCHAR(128) NOT NULL,
    scenario_id VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    total_requests INT NOT NULL DEFAULT 0,
    success_requests INT NOT NULL DEFAULT 0,
    failed_requests INT NOT NULL DEFAULT 0,
    assertions_json TEXT,
    executed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sim_stages_run_id
    ON security_data.simulation_run_stages(run_id);

CREATE INDEX IF NOT EXISTS idx_sim_stages_scenario_id
    ON security_data.simulation_run_stages(scenario_id);

-- 4. Network IP reputation and threat intelligence cache (optional integration)
CREATE TABLE IF NOT EXISTS security_data.network_ip_cache (
    ip_address VARCHAR(45) PRIMARY KEY,
    reputation_status VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    reputation_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    provider VARCHAR(64),
    details TEXT,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    checked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_network_ip_reputation
    ON security_data.network_ip_cache(reputation_status);

CREATE INDEX IF NOT EXISTS idx_network_ip_last_seen
    ON security_data.network_ip_cache(last_seen DESC);
