package com.aegis.gateway.posture.dto;

import java.util.List;

/**
 * Paginated API Security Posture response.
 */
public record PosturePageResponse(
    List<EndpointPostureResponse> content,
    int page,
    int size,
    long totalElements,
    int totalPages,
    boolean hasNext,
    boolean hasPrevious,
    PostureSummaryResponse summary
) {}

