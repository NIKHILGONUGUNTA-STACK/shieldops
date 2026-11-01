package com.aegis.gateway.discovery.dto;

/**
 * Reconciliation contract status between an observed endpoint and active OpenAPI contracts.
 */
public record EndpointReconciliationStatus(
    String category,
    String explanation,
    String matchingConfidence,
    String confidenceRationale
) {}
