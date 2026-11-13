-- Migration: V7__advanced_extraction_telemetry.sql
-- Description: Add observed fields and pagination telemetry fields for Phase 7.2.4.4

ALTER TABLE security_data.api_events ADD COLUMN IF NOT EXISTS observed_fields TEXT;
ALTER TABLE security_data.api_events ADD COLUMN IF NOT EXISTS page_number INT;
ALTER TABLE security_data.api_events ADD COLUMN IF NOT EXISTS page_size INT;
