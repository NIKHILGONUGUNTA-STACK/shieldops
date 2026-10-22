CREATE SCHEMA IF NOT EXISTS security_data;

CREATE TABLE security_data.api_events (
    id UUID PRIMARY KEY,
    correlation_id VARCHAR(64) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    http_method VARCHAR(10) NOT NULL,
    request_path VARCHAR(512) NOT NULL,
    route_id VARCHAR(64),
    status_code INT NOT NULL,
    latency_ms BIGINT NOT NULL,
    auth_subject VARCHAR(128),
    auth_roles VARCHAR(256),
    customer_id VARCHAR(64),
    user_agent VARCHAR(256),
    payload_hash CHAR(64),
    anomaly_flags VARCHAR(128) NOT NULL DEFAULT 'NONE'
);

CREATE INDEX IF NOT EXISTS api_events_correlation_idx ON security_data.api_events(correlation_id);
CREATE INDEX IF NOT EXISTS api_events_timestamp_idx ON security_data.api_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS api_events_subject_idx ON security_data.api_events(auth_subject);
CREATE INDEX IF NOT EXISTS api_events_customer_idx ON security_data.api_events(customer_id);
