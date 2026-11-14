package com.aegis.gateway.detection.policy.dto;

import java.util.List;

public record PolicyDecisionPageResponse(
    List<AdaptivePolicyDecisionResponse> content,
    long totalElements,
    int totalPages,
    int page,
    int size
) {}
