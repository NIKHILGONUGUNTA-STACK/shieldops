package com.aegis.gateway.posture.dto;

/**
 * Categorical overall security posture classification for an endpoint.
 * Kept strictly separate from arbitrary composite scores and confirmed vulnerability assertions.
 */
public enum OverallPosture {
    /** All verifiable dimensions are confirmed with concrete evidence, and zero findings detected. */
    ADEQUATE,

    /** One or more security concerns, discrepancies, or anomalies require analyst attention. */
    ATTENTION_REQUIRED,

    /** Three or more dimensions cannot be evaluated due to insufficient evidence. Missing data is never treated as safe. */
    INSUFFICIENT_EVIDENCE
}

