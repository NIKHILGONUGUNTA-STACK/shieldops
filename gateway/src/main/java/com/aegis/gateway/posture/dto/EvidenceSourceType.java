package com.aegis.gateway.posture.dto;

/**
 * Concrete provenance sources supporting posture assessment dimensions.
 */
public enum EvidenceSourceType {
    OPENAPI_SPEC,
    WIRE_TELEMETRY,
    SECURITY_INCIDENT,
    GATEWAY_CONFIG,
    RECONCILIATION_ENGINE
}

