package com.aegis.gateway.reconciliation.dto;

/**
 * Finding category representing the reconciliation status between declared OpenAPI
 * specifications and live passive wire telemetry.
 */
public enum ReconciliationCategory {
    /**
     * Declared and observed operations match canonical route template and HTTP method.
     */
    MATCHED,

    /**
     * Operation observed in gateway wire telemetry, but absent from the specification scope.
     */
    OBSERVED_UNDOCUMENTED,

    /**
     * Declared operation in specification has no matching observation within the monitoring window.
     */
    DOCUMENTED_UNOBSERVED,

    /**
     * The route is observed, but the observed HTTP method is not declared in the specification.
     */
    METHOD_MISMATCH,

    /**
     * Matching cannot be established safely because multiple specifications or route mappings conflict.
     */
    AMBIGUOUS
}

