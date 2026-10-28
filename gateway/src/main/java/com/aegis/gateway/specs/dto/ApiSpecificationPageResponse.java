package com.aegis.gateway.specs.dto;

import java.util.List;

/**
 * Server-side paginated list of imported OpenAPI specifications.
 */
public record ApiSpecificationPageResponse(
    List<ApiSpecificationResponse> content,
    int page,
    int size,
    long totalElements,
    int totalPages,
    boolean hasNext,
    boolean hasPrevious,
    long totalSpecifications,
    long totalOperations
) {}

