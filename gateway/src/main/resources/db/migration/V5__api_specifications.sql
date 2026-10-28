-- Flyway Migration: V5__api_specifications.sql
-- Description: Schema for Phase 6.2 Secure OpenAPI Specification Import and Declared Operations Inventory

-- 1. Table for imported OpenAPI specifications metadata
CREATE TABLE IF NOT EXISTS security_data.api_specifications (
    id UUID PRIMARY KEY,
    name VARCHAR(256) NOT NULL,
    description TEXT,
    version VARCHAR(64) NOT NULL,
    openapi_version VARCHAR(32) NOT NULL,
    source_filename VARCHAR(256) NOT NULL,
    content_hash CHAR(64) NOT NULL,
    format VARCHAR(16) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    imported_at TIMESTAMP WITH TIME ZONE NOT NULL,
    imported_by VARCHAR(128) NOT NULL,
    operation_count INT NOT NULL DEFAULT 0,
    path_count INT NOT NULL DEFAULT 0,
    validation_summary VARCHAR(512),
    raw_content TEXT
);

CREATE INDEX IF NOT EXISTS api_specs_hash_idx 
    ON security_data.api_specifications(content_hash);

CREATE INDEX IF NOT EXISTS api_specs_imported_at_idx 
    ON security_data.api_specifications(imported_at DESC);

CREATE INDEX IF NOT EXISTS api_specs_name_version_idx 
    ON security_data.api_specifications(name, version);

-- 2. Table for declared operations extracted from OpenAPI specifications
CREATE TABLE IF NOT EXISTS security_data.api_spec_operations (
    id UUID PRIMARY KEY,
    specification_id UUID NOT NULL REFERENCES security_data.api_specifications(id) ON DELETE CASCADE,
    http_method VARCHAR(16) NOT NULL,
    path_pattern VARCHAR(512) NOT NULL,
    normalized_route VARCHAR(256) NOT NULL,
    operation_id VARCHAR(128),
    summary VARCHAR(512),
    description TEXT,
    tags VARCHAR(256),
    deprecated BOOLEAN NOT NULL DEFAULT FALSE,
    service_boundary VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS api_spec_ops_spec_id_idx 
    ON security_data.api_spec_operations(specification_id);

CREATE INDEX IF NOT EXISTS api_spec_ops_method_path_idx 
    ON security_data.api_spec_operations(http_method, path_pattern);

CREATE INDEX IF NOT EXISTS api_spec_ops_normalized_route_idx 
    ON security_data.api_spec_operations(http_method, normalized_route);

