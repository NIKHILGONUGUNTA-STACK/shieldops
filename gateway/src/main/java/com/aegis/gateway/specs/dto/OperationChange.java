package com.aegis.gateway.specs.dto;

import java.util.List;

/**
 * Structural change record for a declared API operation between two specification revisions.
 */
public record OperationChange(
    String changeType, // ADDED, REMOVED, MODIFIED, UNCHANGED
    String httpMethod,
    String pathPattern,
    String normalizedRoute,
    String operationId,
    String summary,
    String description,
    String tags,
    boolean deprecated,
    List<String> diffDetails
) {}
