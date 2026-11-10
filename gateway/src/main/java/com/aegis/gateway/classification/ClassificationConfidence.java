package com.aegis.gateway.classification;

/**
 * Confidence level of data classification evidence.
 */
public enum ClassificationConfidence {
    /**
     * Confirmed by authoritative schema (OpenAPI 3.x specification, record DTO, or explicit policy rule).
     */
    CONFIRMED,

    /**
     * Provisionally classified via semantic heuristic or pattern matching.
     */
    PROVISIONAL,

    /**
     * Unclassified or observed field absent from known policies, requiring human review.
     */
    UNKNOWN
}

