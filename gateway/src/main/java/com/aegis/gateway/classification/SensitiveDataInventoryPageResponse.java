package com.aegis.gateway.classification;

import java.util.List;

/**
 * Paginated response wrapper for sensitive data classification inventory.
 */
public record SensitiveDataInventoryPageResponse(
    List<EndpointDataClassification> content,
    int page,
    int size,
    long totalElements,
    int totalPages,
    boolean hasNext,
    boolean hasPrevious
) {
    public SensitiveDataInventoryPageResponse {
        if (content == null) {
            content = List.of();
        }
    }
}

