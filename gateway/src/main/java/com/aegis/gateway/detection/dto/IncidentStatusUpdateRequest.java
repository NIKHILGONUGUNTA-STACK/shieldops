package com.aegis.gateway.detection.dto;

public record IncidentStatusUpdateRequest(
    String status,
    String reason
) {}
