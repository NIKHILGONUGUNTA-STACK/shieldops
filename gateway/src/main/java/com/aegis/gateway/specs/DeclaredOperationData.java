package com.aegis.gateway.specs;

/**
 * Extracted declared API operation from an OpenAPI specification.
 */
public record DeclaredOperationData(
    String httpMethod,
    String pathPattern,
    String normalizedRoute,
    String operationId,
    String summary,
    String description,
    String tags,
    boolean deprecated,
    String serviceBoundary
) {}

