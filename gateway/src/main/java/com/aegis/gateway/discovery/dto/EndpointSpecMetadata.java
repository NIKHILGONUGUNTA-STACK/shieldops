package com.aegis.gateway.discovery.dto;

import java.util.UUID;

/**
 * Declared OpenAPI specification metadata associated with an observed endpoint.
 */
public record EndpointSpecMetadata(
    UUID specificationId,
    String specificationName,
    String specificationVersion,
    int revisionNumber,
    String operationId,
    String summary,
    String description,
    String tags,
    boolean deprecated
) {}
