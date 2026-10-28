package com.aegis.gateway.specs.dto;

import java.util.UUID;

/**
 * Representation of a declared API operation within an OpenAPI specification.
 */
public record DeclaredOperationResponse(
    UUID id,
    UUID specificationId,
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

