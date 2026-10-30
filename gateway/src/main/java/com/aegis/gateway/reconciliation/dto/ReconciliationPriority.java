package com.aegis.gateway.reconciliation.dto;

/**
 * Prioritization levels for API contract discrepancy findings.
 * Calibrated deterministic levels based on category, service criticality,
 * operational exposure, and real security telemetry signals.
 */
public enum ReconciliationPriority {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW
}
