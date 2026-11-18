-- ============================================================================
-- Flyway Migration V10: Enterprise SOC Runtime Operations & Observability Schema
-- Phase 7.3.2: Step 1 - Attribution Telemetry & Durable Simulation Persistence
-- ============================================================================

-- 1. Extend security_data.api_events with nullable attribution & tenant fields
ALTER TABLE security_data.api_events ADD COLUMN IF NOT EXISTS simulation_run_id VARCHAR(64);
ALTER TABLE security_data.api_events ADD COLUMN IF NOT EXISTS simulation_campaign_id VARCHAR(64);
ALTER TABLE security_data.api_events ADD COLUMN IF NOT EXISTS simulation_scenario_id VARCHAR(64);
ALTER TABLE security_data.api_events ADD COLUMN IF NOT EXISTS simulation_stage VARCHAR(64);
ALTER TABLE security_data.api_events ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64);
ALTER TABLE security_data.api_events ADD COLUMN IF NOT EXISTS service_name VARCHAR(64);

-- Query pattern indexes on api_events (only necessary, non-duplicate indexes)
CREATE INDEX IF NOT EXISTS idx_api_events_sim_run_id
    ON security_data.api_events(simulation_run_id);

CREATE INDEX IF NOT EXISTS idx_api_events_tenant_id
    ON security_data.api_events(tenant_id);

CREATE INDEX IF NOT EXISTS idx_api_events_ip_timestamp
    ON security_data.api_events(source_ip, timestamp DESC);

-- 2. Durable Simulation Runs table
CREATE TABLE IF NOT EXISTS security_data.simulation_runs (
    run_id VARCHAR(64) PRIMARY KEY,
    campaign_id VARCHAR(64),
    template_id VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    requested_by VARCHAR(128),
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_heartbeat_at TIMESTAMP WITH TIME ZONE,
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
    failure_reason TEXT,
    stop_reason TEXT,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT chk_sim_runs_status CHECK (status IN ('PENDING', 'RUNNING', 'PAUSED', 'STOPPED', 'COMPLETED', 'INTERRUPTED', 'FAILED'))
);

CREATE INDEX IF NOT EXISTS idx_sim_runs_status
    ON security_data.simulation_runs(status);

CREATE INDEX IF NOT EXISTS idx_sim_runs_template
    ON security_data.simulation_runs(template_id);

CREATE INDEX IF NOT EXISTS idx_sim_runs_start_time
    ON security_data.simulation_runs(start_time DESC);

-- 3. Simulation Run Stages table with explicit uniqueness and foreign key
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
    executed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_sim_stage_run_scenario UNIQUE (run_id, stage_id, scenario_id)
);

CREATE INDEX IF NOT EXISTS idx_sim_stages_run_id
    ON security_data.simulation_run_stages(run_id);

CREATE INDEX IF NOT EXISTS idx_sim_stages_scenario_id
    ON security_data.simulation_run_stages(scenario_id);
