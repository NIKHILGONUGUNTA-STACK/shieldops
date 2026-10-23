package com.aegis.gateway.telemetry;

import java.util.List;

public record SecurityEventPageResponse(
    List<SecurityEventResponse> content,
    int page,
    int size,
    long totalElements,
    int totalPages,
    boolean hasNext,
    boolean hasPrevious
) {}
