package com.aegis.gateway.reconciliation.dto;

import java.util.UUID;

/**
 * Metadata about the declared OpenAPI specification associated with an API route finding.
 */
public record InvestigationSpecMetadata(
    UUID id,
    String name,
    String version,
    String openapiVersion,
    String format,
    String sourceFilename,
    String operationId,
    String summary,
    String description
) {}
