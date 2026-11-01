package com.aegis.gateway.specs.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Metadata and operations response for an imported OpenAPI specification.
 */
public record ApiSpecificationResponse(
    UUID id,
    String name,
    String description,
    String version,
    int revisionNumber,
    String openapiVersion,
    String sourceFilename,
    String contentHash,
    String format,
    String status,
    Instant importedAt,
    String importedBy,
    int operationCount,
    int pathCount,
    String validationSummary,
    List<DeclaredOperationResponse> operations
) {
    /**
     * Backward-compatible constructor without revisionNumber (defaults to 1).
     */
    public ApiSpecificationResponse(
            UUID id,
            String name,
            String description,
            String version,
            String openapiVersion,
            String sourceFilename,
            String contentHash,
            String format,
            String status,
            Instant importedAt,
            String importedBy,
            int operationCount,
            int pathCount,
            String validationSummary,
            List<DeclaredOperationResponse> operations) {
        this(
            id, name, description, version, 1, openapiVersion, sourceFilename,
            contentHash, format, status, importedAt, importedBy,
            operationCount, pathCount, validationSummary, operations
        );
    }

    public ApiSpecificationResponse withOperations(List<DeclaredOperationResponse> ops) {
        return new ApiSpecificationResponse(
            id, name, description, version, revisionNumber, openapiVersion, sourceFilename,
            contentHash, format, status, importedAt, importedBy,
            operationCount, pathCount, validationSummary, ops
        );
    }
}
