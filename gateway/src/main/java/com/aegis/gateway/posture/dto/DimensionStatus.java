package com.aegis.gateway.posture.dto;

/**
 * Categorical status for an individual security posture dimension.
 * STRICT INVARIANT: Missing evidence is never converted into a positive or negative conclusion.
 */
public enum DimensionStatus {
    /** Dimension properties are backed and verified by concrete empirical evidence. */
    VERIFIED,

    /** Active security concern, documentation discrepancy, or anomaly identified. */
    FINDING,

    /** Insufficient empirical evidence to definitively verify or refute security properties. */
    UNKNOWN
}

