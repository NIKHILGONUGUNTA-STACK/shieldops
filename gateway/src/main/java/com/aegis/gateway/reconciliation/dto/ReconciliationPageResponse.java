package com.aegis.gateway.reconciliation.dto;

import java.util.List;

/**
 * Server-side paginated response for reconciled operations with composite summary.
 */
public record ReconciliationPageResponse(
    List<ReconciliationItemResponse> content,
    int page,
    int size,
    long totalElements,
    int totalPages,
    boolean hasNext,
    boolean hasPrevious,
    ReconciliationSummaryResponse summary
) {}

