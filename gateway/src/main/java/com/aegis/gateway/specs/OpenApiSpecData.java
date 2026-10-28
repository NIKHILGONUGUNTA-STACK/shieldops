package com.aegis.gateway.specs;

import java.util.List;

/**
 * Validated OpenAPI specification metadata and its declared operations.
 */
public record OpenApiSpecData(
    String name,
    String description,
    String version,
    String openapiVersion,
    String format,
    String contentHash,
    int operationCount,
    int pathCount,
    String validationSummary,
    List<DeclaredOperationData> operations
) {}

