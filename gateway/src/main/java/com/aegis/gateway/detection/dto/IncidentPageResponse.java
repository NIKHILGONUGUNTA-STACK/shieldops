package com.aegis.gateway.detection.dto;

import java.util.List;

public record IncidentPageResponse(
    List<IncidentResponse> content,
    int page,
    int size,
    long totalElements,
    int totalPages,
    boolean hasNext,
    boolean hasPrevious
) {}
